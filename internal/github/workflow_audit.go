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
	events := extractEvents(mappingValue(rootMap, "on"))
	publishDetected := workflowPublishes(rootMap)
	attestationDetected := workflowHasAttestations(rootMap) || permissionsAllowAttestations(mappingValue(rootMap, "permissions"))

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
			Evidence: map[string]any{
				"event":                 events,
				"publish_step_detected": publishDetected,
				"attestation_detected":  attestationDetected,
			},
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
			Evidence: map[string]any{
				"event":                 events,
				"permissions":           flattenPermissions(permissionsNode),
				"publish_step_detected": publishDetected,
				"attestation_detected":  attestationDetected,
			},
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
			jobPublishes := jobPublishes(jobNode)
			jobAttests := workflowHasAttestations(jobNode) || permissionsAllowAttestations(mappingValue(jobNode, "permissions")) || attestationDetected
			jobPerms := mappingValue(jobNode, "permissions")
			if jobPerms != nil && hasBroadWrite(jobPerms) {
				findings = append(findings, model.Finding{
					RuleID:      "github.workflow.job_permissions.broad",
					Severity:    model.SeverityHigh,
					Category:    model.CategoryGitHub,
					Title:       "Workflow job grants broad write access to GITHUB_TOKEN",
					Message:     "Job " + jobName + " grants write access beyond the minimum required.",
					Remediation: "Reduce job-level permissions or justify the elevated access explicitly.",
					File:        relPath,
					Line:        jobPerms.Line,
					Evidence: map[string]any{
						"event":                 events,
						"job":                   jobName,
						"permissions":           flattenPermissions(jobPerms),
						"publish_step_detected": jobPublishes,
						"attestation_detected":  jobAttests,
					},
					Actions: []model.Action{
						model.ManualAction("Review job-level write permissions and keep only the scopes that are strictly required."),
					},
				})
			}
			if jobPublishes && jobPerms != nil && hasBroadWrite(jobPerms) {
				findings = append(findings, model.Finding{
					RuleID:      "github.workflow.publish.permissions.broad",
					Severity:    model.SeverityHigh,
					Category:    model.CategoryGitHub,
					Title:       "Publish job grants broad write access",
					Message:     "A publish job grants broad write access to GITHUB_TOKEN.",
					Remediation: "Reduce publish job permissions to the minimum scopes required.",
					File:        relPath,
					Line:        jobPerms.Line,
					Evidence: map[string]any{
						"event":                 events,
						"job":                   jobName,
						"permissions":           flattenPermissions(jobPerms),
						"publish_step_detected": true,
						"attestation_detected":  jobAttests,
					},
					Actions: []model.Action{
						model.ManualAction("Limit publish job permissions to the scopes required for release."),
					},
				})
			}
			if containsEvent(events, "pull_request_target") && jobTouchesPRCode(jobNode) {
				findings = append(findings, model.Finding{
					RuleID:      "github.workflow.pull_request_target.unsafe",
					Severity:    model.SeverityHigh,
					Category:    model.CategoryGitHub,
					Title:       "pull_request_target workflow may process untrusted PR code",
					Message:     "This workflow uses pull_request_target and checks out or executes code in a job.",
					Remediation: "Avoid checking out PR code in pull_request_target or split privileged actions into a trusted workflow.",
					File:        relPath,
					Evidence: map[string]any{
						"event":                 events,
						"job":                   jobName,
						"publish_step_detected": jobPublishes,
						"attestation_detected":  jobAttests,
					},
					Actions: []model.Action{
						model.ManualAction("Review the pull_request_target trust boundary and avoid direct PR code execution."),
					},
				})
			}
			if containsEvent(events, "workflow_run") && (jobPublishes || hasBroadWrite(mappingValue(jobNode, "permissions"))) {
				findings = append(findings, model.Finding{
					RuleID:      "github.workflow.workflow_run.privileged",
					Severity:    model.SeverityMedium,
					Category:    model.CategoryGitHub,
					Title:       "workflow_run can trigger a privileged follow-up job",
					Message:     "This workflow_run job appears to cross a trust boundary into privileged work.",
					Remediation: "Isolate privileged follow-up jobs and review the trust boundary explicitly.",
					File:        relPath,
					Evidence: map[string]any{
						"event":                 events,
						"job":                   jobName,
						"permissions":           flattenPermissions(mappingValue(jobNode, "permissions")),
						"publish_step_detected": jobPublishes,
						"attestation_detected":  jobAttests,
					},
					Actions: []model.Action{
						model.ManualAction("Review workflow_run trust boundaries before using it for privileged work."),
					},
				})
			}

			if uses := scalarValue(jobNode, "uses"); uses != "" {
				if finding := unpinnedActionFinding(relPath, uses, mappingValue(jobNode, "uses")); finding != nil {
					finding.Evidence = mergeEvidence(finding.Evidence, map[string]any{
						"event":                 events,
						"job":                   jobName,
						"uses":                  uses,
						"publish_step_detected": jobPublishes,
						"attestation_detected":  jobAttests,
					})
					findings = append(findings, *finding)
				}
			}

			stepsNode := mappingValue(jobNode, "steps")
			if stepsNode != nil && stepsNode.Kind == yaml.SequenceNode {
				for _, step := range stepsNode.Content {
					if uses := scalarValue(step, "uses"); uses != "" {
						if finding := unpinnedActionFinding(relPath, uses, mappingValue(step, "uses")); finding != nil {
							finding.Evidence = mergeEvidence(finding.Evidence, map[string]any{
								"event":                 events,
								"job":                   jobName,
								"uses":                  uses,
								"publish_step_detected": jobPublishes,
								"attestation_detected":  jobAttests,
							})
							findings = append(findings, *finding)
						}
					}
				}
			}
			if jobPublishes && !jobAttests {
				findings = append(findings, model.Finding{
					RuleID:      "github.workflow.publish.attestations.missing",
					Severity:    model.SeverityMedium,
					Category:    model.CategoryGitHub,
					Title:       "Publish workflow lacks attestations",
					Message:     "A publish/release step was detected without a matching attestation step or permission.",
					Remediation: "Add artifact attestations to the publish workflow.",
					File:        relPath,
					Evidence: map[string]any{
						"event":                 events,
						"job":                   jobName,
						"publish_step_detected": true,
						"attestation_detected":  false,
					},
					Actions: []model.Action{
						model.ManualAction("Add artifact attestations or provenance generation to the publish workflow."),
					},
				})
			}
		}
	}

	return findings
}

func extractEvents(node *yaml.Node) []string {
	if node == nil {
		return nil
	}
	var events []string
	switch node.Kind {
	case yaml.ScalarNode:
		if value := strings.TrimSpace(node.Value); value != "" {
			events = append(events, value)
		}
	case yaml.SequenceNode:
		for _, child := range node.Content {
			if value := strings.TrimSpace(child.Value); value != "" {
				events = append(events, value)
			}
		}
	case yaml.MappingNode:
		for i := 0; i < len(node.Content); i += 2 {
			if value := strings.TrimSpace(node.Content[i].Value); value != "" {
				events = append(events, value)
			}
		}
	}
	return events
}

func containsEvent(events []string, target string) bool {
	for _, event := range events {
		if event == target {
			return true
		}
	}
	return false
}

func workflowPublishes(node *yaml.Node) bool {
	if node == nil {
		return false
	}
	stepsNode := mappingValue(node, "steps")
	if stepsNode == nil || stepsNode.Kind != yaml.SequenceNode {
		return false
	}
	for _, step := range stepsNode.Content {
		if stepPublishes(step) {
			return true
		}
	}
	return false
}

func jobPublishes(node *yaml.Node) bool {
	return workflowPublishes(node)
}

func stepPublishes(node *yaml.Node) bool {
	run := strings.ToLower(scalarValue(node, "run"))
	return strings.Contains(run, "npm publish") || strings.Contains(run, "pnpm publish")
}

func workflowHasAttestations(node *yaml.Node) bool {
	if node == nil {
		return false
	}
	stepsNode := mappingValue(node, "steps")
	if stepsNode == nil || stepsNode.Kind != yaml.SequenceNode {
		return false
	}
	for _, step := range stepsNode.Content {
		uses := scalarValue(step, "uses")
		run := strings.ToLower(scalarValue(step, "run"))
		if strings.Contains(uses, "attest-build-provenance") || strings.Contains(run, "attest") {
			return true
		}
	}
	return false
}

func permissionsAllowAttestations(node *yaml.Node) bool {
	if node == nil || node.Kind != yaml.MappingNode {
		return false
	}
	for i := 0; i < len(node.Content); i += 2 {
		scope := strings.TrimSpace(node.Content[i].Value)
		value := strings.ToLower(strings.TrimSpace(node.Content[i+1].Value))
		if scope == "attestations" && value == "write" {
			return true
		}
	}
	return false
}

func jobTouchesPRCode(node *yaml.Node) bool {
	if node == nil {
		return false
	}
	stepsNode := mappingValue(node, "steps")
	if stepsNode == nil || stepsNode.Kind != yaml.SequenceNode {
		return false
	}
	for _, step := range stepsNode.Content {
		uses := scalarValue(step, "uses")
		run := strings.TrimSpace(scalarValue(step, "run"))
		if strings.HasPrefix(uses, "actions/checkout@") || run != "" {
			return true
		}
	}
	return false
}

func flattenPermissions(node *yaml.Node) map[string]string {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	out := map[string]string{}
	for i := 0; i < len(node.Content); i += 2 {
		out[node.Content[i].Value] = node.Content[i+1].Value
	}
	return out
}

func mergeEvidence(base map[string]any, extra map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
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
