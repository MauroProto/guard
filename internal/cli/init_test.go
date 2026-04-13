package cli

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestInitDefaultDoesNotTouchExistingAIDocs(t *testing.T) {
	dir := t.TempDir()
	original := "custom agents doc\n"

	if err := os.WriteFile(filepath.Join(dir, "AGENTS.md"), []byte(original), 0o644); err != nil {
		t.Fatalf("write AGENTS.md: %v", err)
	}

	if err := runInit([]string{"--root", dir, "--no-color"}); err != nil {
		t.Fatalf("expected init to succeed without touching AI docs, got %v", err)
	}

	got, readErr := os.ReadFile(filepath.Join(dir, "AGENTS.md"))
	if readErr != nil {
		t.Fatalf("read AGENTS.md: %v", readErr)
	}
	if string(got) != original {
		t.Fatalf("expected AGENTS.md to remain unchanged, got %q", string(got))
	}

	if _, err := os.Stat(filepath.Join(dir, ".guard", "policy.yaml")); err != nil {
		t.Fatalf("expected policy to be written: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "pnpm-workspace.yaml")); err != nil {
		t.Fatalf("expected workspace to be written: %v", err)
	}
}

func TestInitWithAIDocsRequiresForceToOverwrite(t *testing.T) {
	dir := t.TempDir()
	original := "custom agents doc\n"

	if err := os.WriteFile(filepath.Join(dir, "AGENTS.md"), []byte(original), 0o644); err != nil {
		t.Fatalf("write AGENTS.md: %v", err)
	}

	err := runInit([]string{"--root", dir, "--with-ai-docs", "--no-color"})
	if err == nil {
		t.Fatal("expected init to fail when AI docs already exist without --force")
	}
	if !errors.Is(err, ErrUsage) {
		t.Fatalf("expected ErrUsage, got %v", err)
	}

	got, readErr := os.ReadFile(filepath.Join(dir, "AGENTS.md"))
	if readErr != nil {
		t.Fatalf("read AGENTS.md: %v", readErr)
	}
	if string(got) != original {
		t.Fatalf("expected AGENTS.md to remain unchanged, got %q", string(got))
	}
}
