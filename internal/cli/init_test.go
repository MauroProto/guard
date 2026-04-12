package cli

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestInitDoesNotOverwriteExistingFilesWithoutForce(t *testing.T) {
	dir := t.TempDir()
	original := "custom agents doc\n"

	if err := os.WriteFile(filepath.Join(dir, "AGENTS.md"), []byte(original), 0o644); err != nil {
		t.Fatalf("write AGENTS.md: %v", err)
	}

	err := runInit([]string{"--root", dir, "--no-color"})
	if err == nil {
		t.Fatal("expected init to fail when target files already exist without --force")
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

	if _, statErr := os.Stat(filepath.Join(dir, ".guard", "policy.yaml")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("expected policy not to be written on failure, got %v", statErr)
	}
}
