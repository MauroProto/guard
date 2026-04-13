package diff

import (
	"path/filepath"
	"testing"

	"github.com/MauroProto/guard/internal/model"
)

func TestParseTarget(t *testing.T) {
	got, err := ParseTarget("axios@1.7.9..1.8.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Package != "axios" || got.From != "1.7.9" || got.To != "1.8.0" {
		t.Fatalf("unexpected parse result: %+v", got)
	}
}

func TestParseTargetScoped(t *testing.T) {
	got, err := ParseTarget("@scope/pkg@1.0.0..2.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Package != "@scope/pkg" {
		t.Fatalf("expected @scope/pkg, got %s", got.Package)
	}
}

func TestParseTargetInvalid(t *testing.T) {
	invalid := []string{"", "axios", "axios@", "axios@1.0.0", "axios@1.0.0..", "@1.0.0..2.0.0"}
	for _, s := range invalid {
		_, err := ParseTarget(s)
		if err == nil {
			t.Fatalf("expected error for %q", s)
		}
	}
}

func TestCheckInstallScripts(t *testing.T) {
	from := &PackageContents{
		PackageJSON: map[string]any{"name": "test"},
		Files:       map[string][]byte{},
	}
	to := &PackageContents{
		PackageJSON: map[string]any{
			"name": "test",
			"scripts": map[string]any{
				"postinstall": "node malicious.js",
			},
		},
		Files: map[string][]byte{},
	}

	signals := checkInstallScripts(from, to)
	if len(signals) != 1 {
		t.Fatalf("expected 1 signal, got %d", len(signals))
	}
	if signals[0].ID != "diff.install_script.added" {
		t.Fatalf("expected diff.install_script.added, got %s", signals[0].ID)
	}
	if signals[0].Severity != model.SeverityCritical {
		t.Fatalf("expected critical severity, got %s", signals[0].Severity)
	}
}

func TestCheckRemoteURLs(t *testing.T) {
	from := &PackageContents{
		Files: map[string][]byte{
			"index.js": []byte("module.exports = 42;"),
		},
	}
	to := &PackageContents{
		Files: map[string][]byte{
			"index.js": []byte("const { exec } = require('child_process'); child_process.exec('ls');"),
		},
	}

	signals := checkRemoteURLs(from, to)
	if len(signals) == 0 {
		t.Fatal("expected signals for child_process pattern")
	}
}

func TestCheckBinaries(t *testing.T) {
	from := &PackageContents{
		Files: map[string][]byte{},
	}
	to := &PackageContents{
		Files:    map[string][]byte{"native.node": {0x00, 0x01, 0x02}},
		FileList: []string{"native.node"},
	}

	signals := checkBinaries(from, to)
	if len(signals) != 1 {
		t.Fatalf("expected 1 signal, got %d", len(signals))
	}
	if signals[0].ID != "diff.binary.added" {
		t.Fatalf("expected diff.binary.added, got %s", signals[0].ID)
	}
}

func TestCompareWithFixtures(t *testing.T) {
	beforeDir := filepath.Join("..", "..", "testdata", "diff", "before")
	afterDir := filepath.Join("..", "..", "testdata", "diff", "after")

	from, err := LoadLocalContents(beforeDir)
	if err != nil {
		t.Fatalf("load before: %v", err)
	}
	to, err := LoadLocalContents(afterDir)
	if err != nil {
		t.Fatalf("load after: %v", err)
	}

	result := Compare(Target{Package: "test", From: "1.0.0", To: "2.0.0"}, from, to, []string{"child_process.exec"})

	if len(result.Signals) == 0 {
		t.Fatal("expected signals from fixture comparison")
	}
	if result.Score == 0 {
		t.Fatal("expected non-zero score")
	}

	// Should find install script added (critical)
	hasCritical := false
	for _, s := range result.Signals {
		if s.Severity == model.SeverityCritical {
			hasCritical = true
		}
	}
	if !hasCritical {
		t.Fatal("expected at least one critical signal from fixture")
	}
}

func TestCompareUsesEmptySignalsSliceWhenClean(t *testing.T) {
	from := &PackageContents{Files: map[string][]byte{}}
	to := &PackageContents{Files: map[string][]byte{}}
	result := Compare(Target{Package: "test", From: "1.0.0", To: "1.0.0"}, from, to, nil)
	if result.Signals == nil {
		t.Fatal("expected empty slice, got nil")
	}
}
