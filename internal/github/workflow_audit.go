package github

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"guard/internal/model"
)

var (
	usesPattern        = regexp.MustCompile(`^\s*-?\s*uses:\s*['"]?([^\s'"]+)['"]?`)
	fullSHARefPattern  = regexp.MustCompile(`@([a-fA-F0-9]{40})$`)
	permissionsLine    = regexp.MustCompile(`(?i)^\s*permissions:\s*(.*)$`)
	broadWritePatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)^\s*contents:\s*write\s*$`),
		regexp.MustCompile(`(?i)^\s*permissions:\s*write-all\s*$`),
		regexp.MustCompile(`(?i)^\s*pull-requests:\s*write\s*$`),
		regexp.MustCompile(`(?i)^\s*issues:\s*write\s*$`),
	}
)

// AuditWorkflows scans workflow files for security issues.
func AuditWorkflows(root string, files []string) []model.Finding {
	var findings []model.Finding
	for _, f := range files {
		findings = append(findings, auditSingleWorkflow(root, f)...)
	}
	return findings
}

func auditSingleWorkflow(root, path string) []model.Finding {
	var findings []model.Finding

	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	relPath := rel(root, path)

	scanner := bufio.NewScanner(file)
	lineNum := 0
	hasPermissions := false
	hasBroadWrite := false

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Check for uses: directives with unpinned actions
		if m := usesPattern.FindStringSubmatch(line); m != nil {
			ref := m[1]
			if strings.Contains(ref, "@") && !fullSHARefPattern.MatchString(ref) {
				// Extract action name before @
				actionName := ref
				if idx := strings.Index(ref, "@"); idx > 0 {
					actionName = ref[:idx]
				}
				findings = append(findings, model.Finding{
					RuleID:      "github.workflow.unpinned_action",
					Severity:    model.SeverityHigh,
					Category:    model.CategoryGitHub,
					Title:       "Workflow action is not pinned to a full commit SHA",
					Message:     "Action reference is mutable: " + ref,
					Remediation: "Pin the action to a full 40-character commit SHA.",
					File:        relPath,
					Line:        lineNum,
					Command:     "gh api repos/" + actionName + "/commits/HEAD --jq .sha",
					Evidence:    map[string]any{"uses": ref},
				})
			}
		}

		// Check for permissions block
		if permissionsLine.MatchString(line) {
			hasPermissions = true
		}

		// Check for broad write permissions
		for _, p := range broadWritePatterns {
			if p.MatchString(line) {
				hasBroadWrite = true
				break
			}
		}
	}

	if !hasPermissions {
		findings = append(findings, model.Finding{
			RuleID:      "github.workflow.permissions.missing",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryGitHub,
			Title:       "Workflow does not define explicit token permissions",
			Message:     "The workflow has no top-level permissions block.",
			Remediation: "Add a permissions block after the 'on:' trigger.",
			File:        relPath,
			Command:     `# Add to ` + relPath + `:\npermissions:\n  contents: read`,
		})
	} else if hasBroadWrite {
		findings = append(findings, model.Finding{
			RuleID:      "github.workflow.token_permissions.broad",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryGitHub,
			Title:       "Workflow grants broad write access to GITHUB_TOKEN",
			Message:     "A workflow grants write access without strong justification.",
			Remediation: "Reduce the default token permissions and elevate only where required.",
			File:        relPath,
		})
	}

	return findings
}

func rel(root, path string) string {
	r, err := filepath.Rel(root, path)
	if err != nil {
		return path
	}
	return filepath.ToSlash(r)
}
