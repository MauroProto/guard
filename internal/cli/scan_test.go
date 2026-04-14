package cli

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/MauroProto/guard/internal/config"
	"github.com/MauroProto/guard/internal/engine"
	"github.com/MauroProto/guard/internal/model"
)

func TestRunScanRejectsFilesAndChangedFilesTogether(t *testing.T) {
	err := runScan([]string{"--files", "package.json", "--changed-files", "--format", "json"})
	if !errors.Is(err, ErrUsage) {
		t.Fatalf("expected ErrUsage, got %v", err)
	}
}

func TestRunScanRejectsUnknownScope(t *testing.T) {
	err := runScan([]string{"--scope", "unknown", "--format", "json"})
	if !errors.Is(err, ErrUsage) {
		t.Fatalf("expected ErrUsage, got %v", err)
	}
}

func TestRunScanPassesScopeAndChangedFilesToEngine(t *testing.T) {
	originalScanRepo := scanRepo
	originalChangedFiles := scanChangedFiles
	t.Cleanup(func() {
		scanRepo = originalScanRepo
		scanChangedFiles = originalChangedFiles
	})

	scanChangedFiles = func(_ context.Context, _ string) ([]string, error) {
		return []string{"pnpm-lock.yaml", "package.json"}, nil
	}
	called := false
	scanRepo = func(_ context.Context, _ string, _ *config.Config, opts *engine.ScanOptions) (*model.Report, error) {
		called = true
		if opts.Scope != "deps" {
			t.Fatalf("expected scope deps, got %+v", opts)
		}
		if !opts.ChangedFiles {
			t.Fatalf("expected ChangedFiles to be true, got %+v", opts)
		}
		if strings.Join(opts.Files, ",") != "package.json,pnpm-lock.yaml" {
			t.Fatalf("expected normalized file list, got %+v", opts.Files)
		}
		return &model.Report{
			SchemaVersion: "1",
			Tool:          "guard",
			Version:       "dev",
			Findings:      []model.Finding{},
		}, nil
	}

	stdout := captureStdout(t, func() {
		if err := runScan([]string{"--scope", "deps", "--changed-files", "--format", "json", "--no-color"}); err != nil {
			t.Fatalf("runScan failed: %v", err)
		}
	})
	if !called {
		t.Fatal("expected scanRepo to be called")
	}
	if !strings.Contains(stdout, `"schemaVersion": "1"`) {
		t.Fatalf("expected stable schemaVersion in JSON output, got %q", stdout)
	}
	if !strings.Contains(stdout, `"findings": []`) {
		t.Fatalf("expected empty findings array in JSON output, got %q", stdout)
	}
}
