package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadHealthyConfig(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "healthy")
	cfg, err := Load(root, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Version != 1 {
		t.Fatalf("expected version 1, got %d", cfg.Version)
	}
	if cfg.PNPM.MinimumReleaseAgeMinutes != 1440 {
		t.Fatalf("expected minimumReleaseAge 1440, got %d", cfg.PNPM.MinimumReleaseAgeMinutes)
	}
	if !cfg.PNPM.BlockExoticSubdeps {
		t.Fatal("expected blockExoticSubdeps to be true")
	}
	if !cfg.PNPM.StrictDepBuilds {
		t.Fatal("expected strictDepBuilds to be true")
	}
	if cfg.PNPM.TrustPolicy != "no-downgrade" {
		t.Fatalf("expected trustPolicy no-downgrade, got %s", cfg.PNPM.TrustPolicy)
	}
	if cfg.Enforcement.FailOn != "high" {
		t.Fatalf("expected failOn high, got %s", cfg.Enforcement.FailOn)
	}
}

func TestLoadMissingConfigReturnsDefault(t *testing.T) {
	cfg, err := Load("/nonexistent", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Version != 1 {
		t.Fatalf("expected default version 1, got %d", cfg.Version)
	}
	if cfg.PNPM.MinimumReleaseAgeMinutes != 1440 {
		t.Fatalf("expected default minimumReleaseAge 1440, got %d", cfg.PNPM.MinimumReleaseAgeMinutes)
	}
}

func TestLoadInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	guardDir := filepath.Join(dir, ".guard")
	os.MkdirAll(guardDir, 0o755)
	os.WriteFile(filepath.Join(guardDir, "policy.yaml"), []byte(":::invalid"), 0o644)

	_, err := Load(dir, "")
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestLoadUnsupportedVersion(t *testing.T) {
	dir := t.TempDir()
	guardDir := filepath.Join(dir, ".guard")
	os.MkdirAll(guardDir, 0o755)
	os.WriteFile(filepath.Join(guardDir, "policy.yaml"), []byte("version: 99"), 0o644)

	_, err := Load(dir, "")
	if err == nil {
		t.Fatal("expected error for unsupported version")
	}
}

func TestSaveAndReload(t *testing.T) {
	dir := t.TempDir()
	cfg := Default()
	cfg.Project.Name = "test-roundtrip"
	cfg.PNPM.MinimumReleaseAgeMinutes = 2880

	if err := Save(dir, "", cfg); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	loaded, err := Load(dir, "")
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}
	if loaded.Project.Name != "test-roundtrip" {
		t.Fatalf("expected name test-roundtrip, got %s", loaded.Project.Name)
	}
	if loaded.PNPM.MinimumReleaseAgeMinutes != 2880 {
		t.Fatalf("expected minimumReleaseAge 2880, got %d", loaded.PNPM.MinimumReleaseAgeMinutes)
	}
}

func TestDefault(t *testing.T) {
	cfg := Default()
	if cfg.Version != 1 {
		t.Fatalf("expected version 1, got %d", cfg.Version)
	}
	if cfg.PNPM.MinimumReleaseAgeMinutes != 1440 {
		t.Fatal("default minimumReleaseAge should be 1440")
	}
	if !cfg.PNPM.BlockExoticSubdeps {
		t.Fatal("default blockExoticSubdeps should be true")
	}
	if !cfg.PNPM.StrictDepBuilds {
		t.Fatal("default strictDepBuilds should be true")
	}
	if !cfg.GitHub.RequirePinnedActions {
		t.Fatal("default requirePinnedActions should be true")
	}
}
