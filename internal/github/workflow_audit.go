package github

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/MauroProto/guard/internal/model"
	"gopkg.in/yaml.v3"
)

var fullSHARefPattern = regexp.MustCompile(`@([a-fA-F0-9]{40})$`)

var knownPermissionScopes = map[string]bool{
	"actions":           true,
	"artifact-metadata": true,
	"attestations":      true,
	"checks":            true,
	"contents":          true,
	"deployments":       true,
	"discussions":       true,
	"id-token":          true,
	"issues":            true,
	"models":            true,
	"packages":          true,
	"pages":             true,
	"pull-requests":     true,
	"security-events":   true,
	"statuses":          true,
}

// AuditWorkflows scans workflow files for security issues.
func AuditWorkflows(root string, files []string) []model.Finding {
	var findings []model.Finding
	for _, path := range files {
		findings = append(findings, auditSingleWorkflow(root, path)...)
	}
	return findings
}

func auditSingleWorkflow(root, path string) []model.Finding {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil || len(doc.Content) == 0 {
		return nil
	}

	relPath := rel(root, path)
	rootMap := doc.Content[0]
	var findings []model.Finding

	permissionsNode := mappingValue(rootMap, "permissions")
	if permissionsNode == nil {
		findings = append(findings, model.Finding{
			RuleID:      "github.workflow.permissions.missing",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryGitHub,
			Title:       "Workflow does not define explicit token permissions",
			Message:     "The workflow has no top-level permissions block.",
			Remediation: "Add a top-level permissions block with the minimum scopes required.",
			File:        relPath,
			Actions: []model.Action{
				model.ManualAction("Add a top-level permissions block, for example permissions: { contents: read }."),
			},
		})
	} else if hasBroadWrite(permissionsNode) {
		findings = append(findings, model.Finding{
			RuleID:      "github.workflow.token_permissions.broad",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryGitHub,
			Title:       "Workflow grants broad write access to GITHUB_TOKEN",
			Message:     "The top-level permissions block grants write access beyond the minimum required.",
			Remediation: "Reduce the default token permissions and elevate only where required.",
			File:        relPath,
			Line:        permissionsNode.Line,
			Actions: []model.Action{
				model.ManualAction("Tighten the top-level permissions block to read-only defaults."),
			},
		})
	}

	jobsNode := mappingValue(rootMap, "jobs")
	if jobsNode != nil && jobsNode.Kind == yaml.MappingNode {
		for i := 0; i < len(jobsNode.Content); i += 2 {
			jobName := jobsNode.Content[i].Value
			jobNode := jobsNode.Content[i+1]
			if jobPerms := mappingValue(jobNode, "permissions"); jobPerms != nil && hasBroadWrite(jobPerms) {
				findings = append(findings, model.Finding{
					RuleID:      "github.workflow.job_permissions.broad",
					Severity:    model.SeverityHigh,
					Category:    model.CategoryGitHub,
					Title:       "Workflow job grants broad write access to GITHUB_TOKEN",
					Message:     "Job " + jobName + " grants write access beyond the minimum required.",
					Remediation: "Reduce job-level permissions or justify the elevated access explicitly.",
					File:        relPath,
					Line:        jobPerms.Line,
					Actions: []model.Action{
						model.ManualAction("Review job-level write permissions and keep only the scopes that are strictly required."),
					},
				})
			}

			if uses := scalarValue(jobNode, "uses"); uses != "" {
				if finding := unpinnedActionFinding(relPath, uses, mappingValue(jobNode, "uses")); finding != nil {
					findings = append(findings, *finding)
				}
			}

			stepsNode := mappingValue(jobNode, "steps")
			if stepsNode != nil && stepsNode.Kind == yaml.SequenceNode {
				for _, step := range stepsNode.Content {
					if uses := scalarValue(step, "uses"); uses != "" {
						if finding := unpinnedActionFinding(relPath, uses, mappingValue(step, "uses")); finding != nil {
							findings = append(findings, *finding)
						}
					}
				}
			}
		}
	}

	return findings
}

func unpinnedActionFinding(relPath, ref string, node *yaml.Node) *model.Finding {
	if !strings.Contains(ref, "@") || fullSHARefPattern.MatchString(ref) {
		return nil
	}
	line := 0
	if node != nil {
		line = node.Line
	}
	return &model.Finding{
		RuleID:      "github.workflow.unpinned_action",
		Severity:    model.SeverityHigh,
		Category:    model.CategoryGitHub,
		Title:       "Workflow action is not pinned to a full commit SHA",
		Message:     "Action reference is mutable: " + ref,
		Remediation: "Pin the action or reusable workflow to a full 40-character commit SHA.",
		File:        relPath,
		Line:        line,
		Actions: []model.Action{
			model.ManualAction("Replace " + ref + " with a full 40-character commit SHA."),
		},
		Evidence: map[string]any{"uses": ref},
	}
}

func hasBroadWrite(node *yaml.Node) bool {
	if node == nil {
		return false
	}
	if node.Kind == yaml.ScalarNode {
		return strings.EqualFold(strings.TrimSpace(node.Value), "write-all")
	}
	if node.Kind != yaml.MappingNode {
		return false
	}

	writeScopes := 0
	nonOIDCWriteScopes := 0
	for i := 0; i < len(node.Content); i += 2 {
		scope := strings.TrimSpace(node.Content[i].Value)
		if !knownPermissionScopes[scope] {
			continue
		}
		value := strings.ToLower(strings.TrimSpace(node.Content[i+1].Value))
		if value != "write" {
			continue
		}
		writeScopes++
		if scope != "id-token" {
			nonOIDCWriteScopes++
		}
	}
	if nonOIDCWriteScopes > 0 {
		return true
	}
	return writeScopes > 0 && nonOIDCWriteScopes > 0
}

func mappingValue(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}

func scalarValue(node *yaml.Node, key string) string {
	child := mappingValue(node, key)
	if child == nil {
		return ""
	}
	return strings.TrimSpace(child.Value)
}

func rel(root, path string) string {
	r, err := filepath.Rel(root, path)
	if err != nil {
		return path
	}
	return filepath.ToSlash(r)
}
