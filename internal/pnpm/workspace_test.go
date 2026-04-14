package pnpm

import (
	"os"
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
	if len(ws.Packages) != 1 || ws.Packages[0] != "packages/*" {
		t.Fatalf("default packages should be [packages/*], got %v", ws.Packages)
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

func TestResolvePackageDirsHonorsExcludePatterns(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{
		filepath.Join(root, "packages", "web"),
		filepath.Join(root, "packages", "skip-me"),
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"pkg"}`), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	dirs, err := ResolvePackageDirs(root, []string{"packages/*", "!packages/skip-me"})
	if err != nil {
		t.Fatalf("resolve package dirs: %v", err)
	}
	if len(dirs) != 1 {
		t.Fatalf("expected 1 resolved dir, got %v", dirs)
	}
	if got := filepath.ToSlash(dirs[0]); got != filepath.ToSlash(filepath.Join(root, "packages", "web")) {
		t.Fatalf("unexpected resolved dir %q", got)
	}
}
