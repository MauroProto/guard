package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLintConfigHealthy(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".github", "workflows"), 0o755); err != nil {
		t.Fatal(err)
	}

	issues := Lint(root, Default())
	if len(issues) != 0 {
		t.Fatalf("expected no lint issues, got %+v", issues)
	}
}

func TestLintConfigFindsInvalidAndDeprecatedFields(t *testing.T) {
	root := t.TempDir()
	cfg := Default()
	cfg.Enforcement.FailOn = "severe"
	cfg.GitHub.WorkflowPaths = []string{"missing/workflows"}
	cfg.Diff.FailOnSignals = []string{"unknown_signal"}
	cfg.Baseline.Path = "."
	cfg.Exceptions.Packages = []PackageException{{
		Name:      "sharp",
		Allows:    []string{"build_script"},
		RuleID:    "unknown.rule",
		ExpiresAt: "not-a-date",
	}}
	cfg.Exceptions.Rules = []RuleException{{
		ID:        "unknown.rule",
		ExpiresAt: "2026-04-13",
	}}

	issues := Lint(root, cfg)
	if !hasLintCode(issues, "config.enforcement.failOn.invalid") {
		t.Fatalf("expected invalid failOn issue, got %+v", issues)
	}
	if !hasLintCode(issues, "config.github.workflowPaths.missing") {
		t.Fatalf("expected missing workflowPaths issue, got %+v", issues)
	}
	if !hasLintCodeWithSeverity(issues, "config.github.workflowPaths.missing", "warning") {
		t.Fatalf("expected missing workflowPaths issue to be warning, got %+v", issues)
	}
	if !hasLintCode(issues, "config.diff.failOnSignals.unknown") {
		t.Fatalf("expected unknown failOnSignals issue, got %+v", issues)
	}
	if !hasLintCode(issues, "config.exceptions.packages.name.deprecated") {
		t.Fatalf("expected deprecated name issue, got %+v", issues)
	}
	if !hasLintCode(issues, "config.exceptions.packages.allows.deprecated") {
		t.Fatalf("expected deprecated allows issue, got %+v", issues)
	}
	if !hasLintCode(issues, "config.exceptions.packages.expiresAt.invalid") {
		t.Fatalf("expected invalid expiresAt issue, got %+v", issues)
	}
	if !hasLintCode(issues, "config.baseline.path.invalid") {
		t.Fatalf("expected invalid baseline path issue, got %+v", issues)
	}
	if !hasLintCode(issues, "config.exceptions.packages.ruleId.unknown") {
		t.Fatalf("expected unknown package ruleId issue, got %+v", issues)
	}
	if !hasLintCode(issues, "config.exceptions.rules.id.unknown") {
		t.Fatalf("expected unknown rule exception ID issue, got %+v", issues)
	}
}

func TestLintConfigAllowsMissingDefaultWorkflowDir(t *testing.T) {
	root := t.TempDir()
	issues := Lint(root, Default())
	if !hasLintCodeWithSeverity(issues, "config.github.workflowPaths.missing", "warning") {
		t.Fatalf("expected missing default workflow path warning, got %+v", issues)
	}
}

func hasLintCode(issues []LintIssue, code string) bool {
	for _, issue := range issues {
		if issue.Code == code {
			return true
		}
	}
	return false
}

func hasLintCodeWithSeverity(issues []LintIssue, code, severity string) bool {
	for _, issue := range issues {
		if issue.Code == code && issue.Severity == severity {
			return true
		}
	}
	return false
}
