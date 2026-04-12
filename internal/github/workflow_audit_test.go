package github

import (
	"path/filepath"
	"testing"
)

func TestAuditHealthyWorkflow(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "healthy")
	files := []string{filepath.Join(root, ".github", "workflows", "ci.yml")}
	findings := AuditWorkflows(root, files)
	if len(findings) != 0 {
		t.Fatalf("expected no findings for healthy workflow, got %d: %v", len(findings), findings)
	}
}

func TestAuditMutableAction(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "insecure")
	files := []string{filepath.Join(root, ".github", "workflows", "ci.yml")}
	findings := AuditWorkflows(root, files)

	hasUnpinned := false
	for _, f := range findings {
		if f.RuleID == "github.workflow.unpinned_action" {
			hasUnpinned = true
			if f.Line == 0 {
				t.Error("expected line number for unpinned action finding")
			}
		}
	}
	if !hasUnpinned {
		t.Fatal("expected unpinned_action finding")
	}
}

func TestAuditMissingPermissions(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "insecure")
	files := []string{filepath.Join(root, ".github", "workflows", "ci.yml")}
	findings := AuditWorkflows(root, files)

	hasMissing := false
	for _, f := range findings {
		if f.RuleID == "github.workflow.permissions.missing" {
			hasMissing = true
		}
	}
	if !hasMissing {
		t.Fatal("expected permissions.missing finding")
	}
}

func TestAuditNoFiles(t *testing.T) {
	findings := AuditWorkflows(".", nil)
	if len(findings) != 0 {
		t.Fatalf("expected no findings for no files, got %d", len(findings))
	}
}
