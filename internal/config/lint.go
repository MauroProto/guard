package config

import (
	"os"
	"path/filepath"
	"strconv"
	"time"

	diffpkg "github.com/MauroProto/guard/internal/diff"
	"github.com/MauroProto/guard/internal/rules"
)

type LintIssue struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Path     string `json:"path,omitempty"`
	Message  string `json:"message"`
}

var validSeverityNames = map[string]bool{
	"low":      true,
	"medium":   true,
	"high":     true,
	"critical": true,
}

func Lint(root string, cfg *Config) []LintIssue {
	var issues []LintIssue

	if !validSeverityNames[cfg.Enforcement.FailOn] {
		issues = append(issues, LintIssue{
			Code:     "config.enforcement.failOn.invalid",
			Severity: "error",
			Path:     "enforcement.failOn",
			Message:  "failOn must be one of: low, medium, high, critical",
		})
	}

	knownSignals := diffpkg.KnownSignalNames()
	for _, signal := range cfg.Diff.FailOnSignals {
		if knownSignals[signal] {
			continue
		}
		issues = append(issues, LintIssue{
			Code:     "config.diff.failOnSignals.unknown",
			Severity: "error",
			Path:     "diff.failOnSignals",
			Message:  "unknown diff signal: " + signal,
		})
	}

	for _, rel := range cfg.GitHub.WorkflowPaths {
		path := filepath.Join(root, filepath.FromSlash(rel))
		info, err := os.Stat(path)
		switch {
		case err == nil && !info.IsDir():
			issues = append(issues, LintIssue{
				Code:     "config.github.workflowPaths.missing",
				Severity: "error",
				Path:     "github.workflowPaths",
				Message:  "workflow path is not a directory: " + rel,
			})
		case os.IsNotExist(err):
			issues = append(issues, LintIssue{
				Code:     "config.github.workflowPaths.missing",
				Severity: "warning",
				Path:     "github.workflowPaths",
				Message:  "workflow path does not exist yet: " + rel,
			})
		}
	}

	if cfg.Baseline.Path == "" {
		issues = append(issues, LintIssue{
			Code:     "config.baseline.path.invalid",
			Severity: "error",
			Path:     "baseline.path",
			Message:  "baseline.path must not be empty",
		})
	} else {
		baselinePath := cfg.Baseline.Path
		if !filepath.IsAbs(baselinePath) {
			baselinePath = filepath.Join(root, filepath.FromSlash(baselinePath))
		}
		if info, err := os.Stat(baselinePath); err == nil && info.IsDir() {
			issues = append(issues, LintIssue{
				Code:     "config.baseline.path.invalid",
				Severity: "error",
				Path:     "baseline.path",
				Message:  "baseline.path must point to a file, not a directory",
			})
		}
	}

	for i, ex := range cfg.Exceptions.Rules {
		if ex.ID != "" && !rules.Known(ex.ID) {
			issues = append(issues, LintIssue{
				Code:     "config.exceptions.rules.id.unknown",
				Severity: "error",
				Path:     "exceptions.rules",
				Message:  "unknown rule ID in rule exception #" + itoa(i) + ": " + ex.ID,
			})
		}
		if !validExpiry(ex.ExpiresAt) {
			issues = append(issues, LintIssue{
				Code:     "config.exceptions.rules.expiresAt.invalid",
				Severity: "error",
				Path:     "exceptions.rules",
				Message:  "invalid expiresAt for rule exception #" + itoa(i),
			})
		}
	}

	for i, ex := range cfg.Exceptions.Packages {
		if ex.Name != "" && ex.Package == "" {
			issues = append(issues, LintIssue{
				Code:     "config.exceptions.packages.name.deprecated",
				Severity: "warning",
				Path:     "exceptions.packages",
				Message:  "legacy field exceptions.packages[].name is deprecated; use package",
			})
		}
		if len(ex.Allows) > 0 {
			issues = append(issues, LintIssue{
				Code:     "config.exceptions.packages.allows.deprecated",
				Severity: "warning",
				Path:     "exceptions.packages",
				Message:  "legacy field exceptions.packages[].allows is deprecated; use kind",
			})
		}
		if ex.RuleID != "" && !rules.Known(ex.RuleID) {
			issues = append(issues, LintIssue{
				Code:     "config.exceptions.packages.ruleId.unknown",
				Severity: "error",
				Path:     "exceptions.packages",
				Message:  "unknown ruleId for package exception #" + itoa(i) + ": " + ex.RuleID,
			})
		}
		if !validExpiry(ex.ExpiresAt) {
			issues = append(issues, LintIssue{
				Code:     "config.exceptions.packages.expiresAt.invalid",
				Severity: "error",
				Path:     "exceptions.packages",
				Message:  "invalid expiresAt for package exception #" + itoa(i),
			})
		}
	}

	return issues
}

func validExpiry(value string) bool {
	if value == "" {
		return true
	}
	if _, err := time.Parse(time.RFC3339, value); err == nil {
		return true
	}
	if _, err := time.Parse("2006-01-02", value); err == nil {
		return true
	}
	return false
}

func itoa(v int) string {
	return strconv.Itoa(v)
}
