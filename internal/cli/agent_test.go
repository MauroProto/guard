package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunAgentAuditOutputsJSONFindings(t *testing.T) {
	root := t.TempDir()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	settings := `{
  "mcpServers": {
    "docs": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/"]
    }
  }
}`
	if err := os.WriteFile(filepath.Join(root, ".claude", "settings.json"), []byte(settings), 0o644); err != nil {
		t.Fatal(err)
	}

	stdout := captureStdout(t, func() {
		err := runAgent([]string{"audit", "--root", root, "--home", home, "--format", "json", "--no-color"})
		if !errors.Is(err, ErrPolicy) {
			t.Fatalf("expected ErrPolicy, got %v", err)
		}
	})
	if !strings.Contains(stdout, `"tool": "guard-agent-audit"`) {
		t.Fatalf("expected agent audit report, got %q", stdout)
	}
	if !strings.Contains(stdout, `"rule_id": "agent.mcp.unpinned_npx"`) {
		t.Fatalf("expected unpinned npx finding, got %q", stdout)
	}
	if !strings.Contains(stdout, `"rule_id": "agent.mcp.filesystem_broad"`) {
		t.Fatalf("expected filesystem finding, got %q", stdout)
	}
}

func TestRunAgentAuditCanRunNonBlocking(t *testing.T) {
	root := t.TempDir()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	settings := `{
  "mcpServers": {
    "docs": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/"]
    }
  }
}`
	if err := os.WriteFile(filepath.Join(root, ".claude", "settings.json"), []byte(settings), 0o644); err != nil {
		t.Fatal(err)
	}

	stdout := captureStdout(t, func() {
		if err := runAgent([]string{"audit", "--root", root, "--home", home, "--format", "json", "--fail-on", "none", "--no-color"}); err != nil {
			t.Fatalf("expected non-blocking audit, got %v", err)
		}
	})
	if !strings.Contains(stdout, `"decision": "pass"`) {
		t.Fatalf("expected pass decision with --fail-on none, got %q", stdout)
	}
}
