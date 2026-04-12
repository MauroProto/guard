package pnpm

import (
	"path/filepath"
	"testing"
)

func TestLoadHealthyWorkspace(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "healthy")
	ws, err := Load(root)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ws.MinimumReleaseAge != 1440 {
		t.Fatalf("expected minimumReleaseAge 1440, got %d", ws.MinimumReleaseAge)
	}
	if !ws.BlockExoticSubdeps {
		t.Fatal("expected blockExoticSubdeps true")
	}
	if !ws.StrictDepBuilds {
		t.Fatal("expected strictDepBuilds true")
	}
	if ws.TrustPolicy != "no-downgrade" {
		t.Fatalf("expected trustPolicy no-downgrade, got %s", ws.TrustPolicy)
	}
}

func TestLoadInsecureWorkspace(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "insecure")
	ws, err := Load(root)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ws.MinimumReleaseAge != 60 {
		t.Fatalf("expected minimumReleaseAge 60, got %d", ws.MinimumReleaseAge)
	}
	if ws.BlockExoticSubdeps {
		t.Fatal("expected blockExoticSubdeps false")
	}
	if ws.StrictDepBuilds {
		t.Fatal("expected strictDepBuilds false")
	}
	allowed, ok := ws.AllowBuilds["sharp"]
	if !ok {
		t.Fatal("expected sharp in allowBuilds")
	}
	if allowed {
		t.Fatal("expected sharp allowBuilds to be false")
	}
}

func TestDefaultWorkspace(t *testing.T) {
	ws := DefaultWorkspace()
	if ws.MinimumReleaseAge != 1440 {
		t.Fatal("default minimumReleaseAge should be 1440")
	}
	if !ws.BlockExoticSubdeps {
		t.Fatal("default blockExoticSubdeps should be true")
	}
	if !ws.StrictDepBuilds {
		t.Fatal("default strictDepBuilds should be true")
	}
}

func TestSaveAndReloadWorkspace(t *testing.T) {
	dir := t.TempDir()
	ws := DefaultWorkspace()
	ws.MinimumReleaseAge = 2880
	ws.Packages = []string{"packages/*"}

	if err := Save(dir, ws); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	loaded, err := Load(dir)
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}
	if loaded.MinimumReleaseAge != 2880 {
		t.Fatalf("expected 2880, got %d", loaded.MinimumReleaseAge)
	}
	if len(loaded.Packages) != 1 || loaded.Packages[0] != "packages/*" {
		t.Fatalf("unexpected packages: %v", loaded.Packages)
	}
}
