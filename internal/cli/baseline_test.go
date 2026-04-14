package cli

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/MauroProto/guard/internal/config"
	"github.com/MauroProto/guard/internal/engine"
	"github.com/MauroProto/guard/internal/model"
)

func TestRunBaselineRecordDoesNotForceDisableOSV(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".guard"), 0o755); err != nil {
		t.Fatal(err)
	}
	policy := `version: 1
osv:
  enabled: true
`
	if err := os.WriteFile(filepath.Join(root, ".guard", "policy.yaml"), []byte(policy), 0o644); err != nil {
		t.Fatal(err)
	}

	original := baselineScanRepo
	t.Cleanup(func() {
		baselineScanRepo = original
	})

	called := false
	baselineScanRepo = func(_ context.Context, _ string, _ *config.Config, opts *engine.ScanOptions) (*model.Report, error) {
		called = true
		if opts == nil {
			t.Fatal("expected scan options")
		}
		if opts.DisableOSV {
			t.Fatal("expected baseline record to respect OSV policy instead of forcing DisableOSV")
		}
		return &model.Report{Findings: []model.Finding{}}, nil
	}

	captureStdout(t, func() {
		if err := runBaseline([]string{"record", "--root", root}); err != nil {
			t.Fatalf("baseline record failed: %v", err)
		}
	})

	if !called {
		t.Fatal("expected baseline record to invoke scan")
	}
	if _, err := os.Stat(filepath.Join(root, ".guard", "baseline.json")); err != nil {
		t.Fatalf("expected baseline.json to be written, got %v", err)
	}
}
