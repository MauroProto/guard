package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/MauroProto/guard/internal/config"
	"github.com/MauroProto/guard/internal/model"
	"github.com/MauroProto/guard/internal/pnpm"
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

func TestScanWorkspacePackages(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "pnpm-workspace.yaml"), []byte("packages:\n  - apps/*\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "pnpm-lock.yaml"), []byte("lockfileVersion: '9.0'\npackages: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "apps", "web"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "apps", "web", "package.json"), []byte(`{"name":"web-app"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	rep, err := ScanRepo(context.Background(), root, cfg, &ScanOptions{DisableOSV: true})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	var foundPackageManager bool
	var foundNodeEngine bool
	for _, finding := range rep.Findings {
		if finding.File == "apps/web/package.json" && finding.RuleID == "repo.packageManager.unpinned" {
			foundPackageManager = true
		}
		if finding.File == "apps/web/package.json" && finding.RuleID == "repo.nodeEngine.missing" {
			foundNodeEngine = true
		}
	}
	if !foundPackageManager || !foundNodeEngine {
		t.Fatalf("expected workspace package findings, got %+v", rep.Findings)
	}
}

func TestUnreviewedBuildWithUnsafePackageNameStaysManual(t *testing.T) {
	cfg := config.Default()
	ws := &pnpm.Workspace{
		MinimumReleaseAge:  cfg.PNPM.MinimumReleaseAgeMinutes,
		BlockExoticSubdeps: true,
		StrictDepBuilds:    true,
		TrustPolicy:        cfg.PNPM.TrustPolicy,
		AllowBuilds: map[string]bool{
			"bad;touch /tmp/pwned": false,
		},
	}
	report := NewReport(".")
	checkPNPM(report, cfg, ws)

	if len(report.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(report.Findings))
	}
	action := report.Findings[0].PrimaryAction()
	if action == nil || action.Type != model.ActionTypeManual {
		t.Fatalf("expected manual action, got %+v", action)
	}
}
