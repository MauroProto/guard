package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunPolicyLintPassesValidConfig(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".github", "workflows"), 0o755); err != nil {
		t.Fatal(err)
	}
	policy := `version: 1
enforcement:
  failOn: high
github:
  workflowPaths:
    - .github/workflows
diff:
  enabled: true
  failOnSignals:
    - diff.install_script.added
`
	configPath := filepath.Join(root, "policy.yaml")
	if err := os.WriteFile(configPath, []byte(policy), 0o644); err != nil {
		t.Fatal(err)
	}

	stdout := captureStdout(t, func() {
		if err := runPolicy([]string{"lint", "--root", root, "--config", configPath, "--no-color"}); err != nil {
			t.Fatalf("expected lint to pass, got %v", err)
		}
	})
	if !strings.Contains(stdout, "Policy lint passed.") {
		t.Fatalf("expected success output, got %q", stdout)
	}
}

func TestRunPolicyLintReturnsJSONIssues(t *testing.T) {
	root := t.TempDir()
	policy := `version: 1
enforcement:
  failOn: urgent
github:
  workflowPaths:
    - missing/workflows
`
	configPath := filepath.Join(root, "policy.yaml")
	if err := os.WriteFile(configPath, []byte(policy), 0o644); err != nil {
		t.Fatal(err)
	}

	stdout := captureStdout(t, func() {
		err := runPolicy([]string{"lint", "--root", root, "--config", configPath, "--format", "json", "--no-color"})
		if !errors.Is(err, ErrPolicy) {
			t.Fatalf("expected ErrPolicy, got %v", err)
		}
	})
	if !strings.Contains(stdout, `"schemaVersion": "1"`) {
		t.Fatalf("expected schemaVersion in json output, got %q", stdout)
	}
	if !strings.Contains(stdout, `"code": "config.enforcement.failOn.invalid"`) {
		t.Fatalf("expected failOn lint code in json output, got %q", stdout)
	}
}

func TestRunPolicyLintWarningsDoNotFail(t *testing.T) {
	root := t.TempDir()
	policy := `version: 1
github:
  workflowPaths:
    - .github/workflows
`
	configPath := filepath.Join(root, "policy.yaml")
	if err := os.WriteFile(configPath, []byte(policy), 0o644); err != nil {
		t.Fatal(err)
	}

	stdout := captureStdout(t, func() {
		if err := runPolicy([]string{"lint", "--root", root, "--config", configPath, "--no-color"}); err != nil {
			t.Fatalf("expected warning-only lint to pass, got %v", err)
		}
	})
	if !strings.Contains(stdout, "[WARNING] workflow path does not exist yet: .github/workflows") {
		t.Fatalf("expected warning output, got %q", stdout)
	}
}
