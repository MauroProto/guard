package github

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/MauroProto/guard/internal/model"
)

func TestAuditHealthyWorkflow(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "healthy")
	files := []string{filepath.Join(root, ".github", "workflows", "ci.yml")}
	findings := AuditWorkflows(root, files)
	if len(findings) != 0 {
		t.Fatalf("expected no findings for healthy workflow, got %d: %v", len(findings), findings)
	}
}

func TestAuditJobPermissionsDoNotSatisfyTopLevelRequirement(t *testing.T) {
	root := t.TempDir()
	workflowPath := filepath.Join(root, ".github", "workflows", "ci.yml")
	if err := os.MkdirAll(filepath.Dir(workflowPath), 0o755); err != nil {
		t.Fatal(err)
	}
	workflow := `name: CI
on: [push]
jobs:
  build:
    permissions:
      contents: read
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd
`
	if err := os.WriteFile(workflowPath, []byte(workflow), 0o644); err != nil {
		t.Fatal(err)
	}

	findings := AuditWorkflows(root, []string{workflowPath})
	if !hasRule(findings, "github.workflow.permissions.missing") {
		t.Fatal("expected permissions.missing finding")
	}
}

func TestAuditJobBroadPermissions(t *testing.T) {
	root := t.TempDir()
	workflowPath := filepath.Join(root, ".github", "workflows", "release.yml")
	if err := os.MkdirAll(filepath.Dir(workflowPath), 0o755); err != nil {
		t.Fatal(err)
	}
	workflow := `name: Release
on: [push]
permissions:
  contents: read
jobs:
  publish:
    permissions:
      packages: write
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd
`
	if err := os.WriteFile(workflowPath, []byte(workflow), 0o644); err != nil {
		t.Fatal(err)
	}

	findings := AuditWorkflows(root, []string{workflowPath})
	if !hasRule(findings, "github.workflow.job_permissions.broad") {
		t.Fatal("expected job_permissions.broad finding")
	}
}

func TestAuditAllowsOIDCOnly(t *testing.T) {
	root := t.TempDir()
	workflowPath := filepath.Join(root, ".github", "workflows", "deploy.yml")
	if err := os.MkdirAll(filepath.Dir(workflowPath), 0o755); err != nil {
		t.Fatal(err)
	}
	workflow := `name: Deploy
on: [push]
permissions:
  contents: read
  id-token: write
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd
`
	if err := os.WriteFile(workflowPath, []byte(workflow), 0o644); err != nil {
		t.Fatal(err)
	}

	findings := AuditWorkflows(root, []string{workflowPath})
	if hasRule(findings, "github.workflow.token_permissions.broad") {
		t.Fatal("did not expect broad token finding for contents:read + id-token:write")
	}
}

func TestAuditReusableWorkflowPinningIsManual(t *testing.T) {
	root := t.TempDir()
	workflowPath := filepath.Join(root, ".github", "workflows", "reuse.yml")
	if err := os.MkdirAll(filepath.Dir(workflowPath), 0o755); err != nil {
		t.Fatal(err)
	}
	workflow := `name: Reuse
on: [push]
permissions:
  contents: read
jobs:
  reuse:
    uses: org/workflows/.github/workflows/release.yml@main
`
	if err := os.WriteFile(workflowPath, []byte(workflow), 0o644); err != nil {
		t.Fatal(err)
	}

	findings := AuditWorkflows(root, []string{workflowPath})
	if !hasRule(findings, "github.workflow.unpinned_action") {
		t.Fatal("expected unpinned_action finding")
	}
	for _, finding := range findings {
		if finding.RuleID == "github.workflow.unpinned_action" {
			if action := finding.PrimaryAction(); action == nil || action.Type != "manual" {
				t.Fatalf("expected manual remediation for unpinned action, got %+v", action)
			}
		}
	}
}

func TestAuditNoFiles(t *testing.T) {
	findings := AuditWorkflows(".", nil)
	if len(findings) != 0 {
		t.Fatalf("expected no findings for no files, got %d", len(findings))
	}
}

func hasRule(findings []model.Finding, ruleID string) bool {
	for _, finding := range findings {
		if finding.RuleID == ruleID {
			return true
		}
	}
	return false
}
