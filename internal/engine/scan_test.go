package engine

import (
	"context"
	"path/filepath"
	"testing"

	"guard/internal/config"
	"guard/internal/model"
)

func TestScanHealthyRepo(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "healthy")
	cfg, err := config.Load(root, "")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	rep, err := ScanRepo(context.Background(), root, cfg, nil)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	if rep.HasBlockingFindings() {
		t.Fatal("healthy repo should not have blocking findings")
	}
	if rep.Decision != "pass" {
		t.Fatalf("expected pass, got %s", rep.Decision)
	}
	if rep.Score != 0 {
		t.Fatalf("expected score 0, got %d", rep.Score)
	}
}

func TestScanInsecureRepo(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "insecure")
	cfg, err := config.Load(root, "")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	rep, err := ScanRepo(context.Background(), root, cfg, nil)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	if !rep.HasBlockingFindings() {
		t.Fatal("insecure repo should have blocking findings")
	}
	if rep.Decision != "fail" {
		t.Fatalf("expected fail, got %s", rep.Decision)
	}
	if rep.Score == 0 {
		t.Fatal("expected non-zero score")
	}
}

func TestScanWithFailOnOverride(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "insecure")
	cfg, err := config.Load(root, "")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	// Set failOn to critical - only critical findings should block
	opts := &ScanOptions{FailOn: "critical"}
	rep, err := ScanRepo(context.Background(), root, cfg, opts)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	// Since insecure repo has no critical findings, nothing should block
	if rep.HasBlockingFindings() {
		t.Fatal("with failOn=critical, insecure repo should not have blocking findings")
	}
}

func TestScoreCalculation(t *testing.T) {
	findings := []model.Finding{
		{Severity: model.SeverityCritical},
		{Severity: model.SeverityHigh},
		{Severity: model.SeverityMedium},
		{Severity: model.SeverityLow},
	}
	s := score(findings)
	expected := 40 + 20 + 8 + 3 // 71
	if s != expected {
		t.Fatalf("expected score %d, got %d", expected, s)
	}
}

func TestScoreCap(t *testing.T) {
	findings := []model.Finding{
		{Severity: model.SeverityCritical},
		{Severity: model.SeverityCritical},
		{Severity: model.SeverityCritical},
	}
	s := score(findings)
	if s != 100 {
		t.Fatalf("expected capped score 100, got %d", s)
	}
}

func TestScoreMutedFindingsExcluded(t *testing.T) {
	findings := []model.Finding{
		{Severity: model.SeverityHigh, Muted: true},
		{Severity: model.SeverityMedium},
	}
	s := score(findings)
	if s != 8 {
		t.Fatalf("expected score 8 (muted high excluded), got %d", s)
	}
}
