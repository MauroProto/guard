package cli

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/MauroProto/guard/internal/config"
	"github.com/MauroProto/guard/internal/pnpm"
)

func TestApproveBuildRejectsAmbiguousImporter(t *testing.T) {
	root := t.TempDir()
	writeApproveBuildFixture(t, root, "packages:\n  - packages/*\nallowBuilds:\n  sharp: false\n", `lockfileVersion: '9.0'
importers:
  packages/web:
    dependencies:
      sharp:
        version: 1.2.3
  packages/api:
    dependencies:
      sharp:
        version: 1.2.3
packages: {}
`)

	err := runApproveBuild([]string{"sharp", "--root", root, "--no-color"})
	if err == nil {
		t.Fatal("expected ambiguous importer approval to fail")
	}
	if !errors.Is(err, ErrUsage) {
		t.Fatalf("expected ErrUsage, got %v", err)
	}
}

func TestApproveBuildWritesScopedCanonicalException(t *testing.T) {
	root := t.TempDir()
	writeApproveBuildFixture(t, root, "packages:\n  - packages/*\nallowBuilds:\n  sharp: false\n", `lockfileVersion: '9.0'
importers:
  packages/web:
    dependencies:
      sharp:
        version: 1.2.3
packages: {}
`)

	if err := runApproveBuild([]string{"sharp", "--root", root, "--importer", "packages/web", "--approved-by", "mauro", "--no-color"}); err != nil {
		t.Fatalf("approve-build failed: %v", err)
	}

	cfg, err := config.Load(root, "")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if len(cfg.Exceptions.Packages) != 1 {
		t.Fatalf("expected 1 package exception, got %d", len(cfg.Exceptions.Packages))
	}
	ex := cfg.Exceptions.Packages[0]
	if ex.Package != "sharp" || ex.Name != "sharp" {
		t.Fatalf("expected mirrored package/name sharp, got %+v", ex)
	}
	if ex.Kind != "build_script" {
		t.Fatalf("expected build_script kind, got %+v", ex)
	}
	if ex.Version != "1.2.3" {
		t.Fatalf("expected version 1.2.3, got %+v", ex)
	}
	if ex.Importer != "packages/web" {
		t.Fatalf("expected importer packages/web, got %+v", ex)
	}
	if ex.RuleID != "pnpm.allowBuilds.unreviewed" {
		t.Fatalf("expected ruleId pnpm.allowBuilds.unreviewed, got %+v", ex)
	}
	if ex.ApprovedBy != "mauro" {
		t.Fatalf("expected approvedBy mauro, got %+v", ex)
	}
	if ex.ApprovedAt == "" || ex.ExpiresAt == "" {
		t.Fatalf("expected approvedAt/expiresAt to be set, got %+v", ex)
	}

	ws, err := pnpm.Load(root)
	if err != nil {
		t.Fatalf("load workspace: %v", err)
	}
	if !ws.AllowBuilds["sharp"] {
		t.Fatal("expected allowBuilds[sharp] to be true")
	}
}

func writeApproveBuildFixture(t *testing.T, root, workspaceYAML, lockfileYAML string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, ".guard"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "pnpm-workspace.yaml"), []byte(workspaceYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "pnpm-lock.yaml"), []byte(lockfileYAML), 0o644); err != nil {
		t.Fatal(err)
	}
}
