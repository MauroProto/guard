package cli

import (
	"strings"
	"testing"
)

func TestExplainRuleIDJSON(t *testing.T) {
	stdout := captureStdout(t, func() {
		if err := runExplain([]string{"--format", "json", "review.diff.install_script.added"}); err != nil {
			t.Fatalf("runExplain failed: %v", err)
		}
	})
	if !strings.Contains(stdout, `"rule_id": "review.diff.install_script.added"`) {
		t.Fatalf("expected rule id in output, got %q", stdout)
	}
	if !strings.Contains(stdout, `"description"`) {
		t.Fatalf("expected description in output, got %q", stdout)
	}
}
