package engine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/MauroProto/guard/internal/config"
	"github.com/MauroProto/guard/internal/model"
	"github.com/MauroProto/guard/internal/osv"
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

func TestScanOSVFailureAddsIncompleteDiagnostic(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"name":"app","packageManager":"pnpm@10.20.0","engines":{"node":">=22"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	lock := `lockfileVersion: '9.0'
packages:
  /left-pad@1.0.0:
    resolution: {}
`
	if err := os.WriteFile(filepath.Join(root, "pnpm-lock.yaml"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	cfg.OSV.Enabled = true
	rep, err := ScanRepo(context.Background(), root, cfg, &ScanOptions{
		Scope:     "deps",
		OSVClient: failingOSVClient{},
	})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	var diagnostic *model.Finding
	for i := range rep.Findings {
		if rep.Findings[i].RuleID == "osv.scan.incomplete" {
			diagnostic = &rep.Findings[i]
			break
		}
	}
	if diagnostic == nil {
		t.Fatalf("expected osv.scan.incomplete diagnostic, got %+v", rep.Findings)
	}
	if diagnostic.Blocking {
		t.Fatalf("expected diagnostic to be non-blocking, got %+v", diagnostic)
	}
	if diagnostic.Evidence["failed_package"] != "left-pad@1.0.0" {
		t.Fatalf("expected failed package evidence, got %+v", diagnostic.Evidence)
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
	checkWorkspacePosture(report, cfg, ws)
	checkPendingBuildApprovals(report, cfg, ".", ws)

	if len(report.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(report.Findings))
	}
	action := report.Findings[0].PrimaryAction()
	if action == nil || action.Type != model.ActionTypeManual {
		t.Fatalf("expected manual action, got %+v", action)
	}
}

type failingOSVClient struct{}

func (failingOSVClient) Query(context.Context, osv.Query) ([]osv.Advisory, error) {
	return nil, errors.New("osv unavailable")
}

func TestScanUsesConfiguredWorkflowPaths(t *testing.T) {
	root := t.TempDir()
	workflowPath := filepath.Join(root, ".ci", "workflows", "custom.yml")
	if err := os.MkdirAll(filepath.Dir(workflowPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"name":"app","packageManager":"pnpm@10.20.0","engines":{"node":">=22"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "pnpm-lock.yaml"), []byte("lockfileVersion: '9.0'\npackages: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "pnpm-workspace.yaml"), []byte("packages:\n  - packages/*\nminimumReleaseAge: 1440\ntrustPolicy: no-downgrade\nblockExoticSubdeps: true\nstrictDepBuilds: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	workflow := `name: CI
on: [push]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@main
`
	if err := os.WriteFile(workflowPath, []byte(workflow), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	cfg.GitHub.WorkflowPaths = []string{".ci/workflows"}
	rep, err := ScanRepo(context.Background(), root, cfg, &ScanOptions{DisableOSV: true})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	found := false
	for _, finding := range rep.Findings {
		if finding.RuleID == "github.workflow.unpinned_action" && finding.File == ".ci/workflows/custom.yml" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected workflow in custom path to be audited, got %+v", rep.Findings)
	}
}

func TestScanHonorsGitHubRuleGates(t *testing.T) {
	root := t.TempDir()
	workflowPath := filepath.Join(root, ".github", "workflows", "ci.yml")
	if err := os.MkdirAll(filepath.Dir(workflowPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"name":"app","packageManager":"pnpm@10.20.0","engines":{"node":">=22"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "pnpm-lock.yaml"), []byte("lockfileVersion: '9.0'\npackages: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "pnpm-workspace.yaml"), []byte("packages:\n  - packages/*\nminimumReleaseAge: 1440\ntrustPolicy: no-downgrade\nblockExoticSubdeps: true\nstrictDepBuilds: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	workflow := `name: CI
on: [push]
jobs:
  test:
    permissions:
      packages: write
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@main
`
	if err := os.WriteFile(workflowPath, []byte(workflow), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	cfg.GitHub.RequirePinnedActions = false
	cfg.GitHub.RequireReadOnlyDefaultToken = false
	rep, err := ScanRepo(context.Background(), root, cfg, &ScanOptions{DisableOSV: true})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	for _, finding := range rep.Findings {
		if finding.RuleID == "github.workflow.unpinned_action" || finding.RuleID == "github.workflow.permissions.missing" || finding.RuleID == "github.workflow.job_permissions.broad" || finding.RuleID == "github.workflow.token_permissions.broad" {
			t.Fatalf("did not expect gated GitHub finding %s", finding.RuleID)
		}
	}
}

func TestScanScopePolicyOnly(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".guard"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, ".github", "workflows"), 0o755); err != nil {
		t.Fatal(err)
	}
	policyYAML := `version: 1
diff:
  failOnSignals:
    - definitely-not-a-real-signal
`
	if err := os.WriteFile(filepath.Join(root, ".guard", "policy.yaml"), []byte(policyYAML), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Load(root, "")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	rep, err := ScanRepo(context.Background(), root, cfg, &ScanOptions{Scope: "policy", DisableOSV: true})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	if len(rep.Findings) != 1 {
		t.Fatalf("expected exactly one policy finding, got %+v", rep.Findings)
	}
	if rep.Findings[0].RuleID != "config.diff.failOnSignals.unknown" {
		t.Fatalf("expected policy lint finding, got %+v", rep.Findings)
	}
}

func TestScanFilesWorkflowOnlySkipsPackageMetadata(t *testing.T) {
	root := writeFocusedScanFixture(t)
	cfg := config.Default()
	rep, err := ScanRepo(context.Background(), root, cfg, &ScanOptions{
		Scope:      "all",
		Files:      []string{".github/workflows/ci.yml"},
		DisableOSV: true,
	})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	expectFinding(t, rep.Findings, "github.workflow.unpinned_action")
	expectNoFinding(t, rep.Findings, "repo.packageManager.unpinned")
	expectNoFinding(t, rep.Findings, "repo.nodeEngine.missing")
}

func TestScanFilesPackageJSONOnlySkipsWorkflowAudit(t *testing.T) {
	root := writeFocusedScanFixture(t)
	cfg := config.Default()
	rep, err := ScanRepo(context.Background(), root, cfg, &ScanOptions{
		Scope:      "all",
		Files:      []string{"package.json"},
		DisableOSV: true,
	})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	expectFinding(t, rep.Findings, "repo.packageManager.unpinned")
	expectFinding(t, rep.Findings, "repo.nodeEngine.missing")
	expectNoFinding(t, rep.Findings, "github.workflow.unpinned_action")
}

func writeFocusedScanFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	workflowPath := filepath.Join(root, ".github", "workflows", "ci.yml")
	if err := os.MkdirAll(filepath.Dir(workflowPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"name":"app"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "pnpm-lock.yaml"), []byte("lockfileVersion: '9.0'\npackages: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "pnpm-workspace.yaml"), []byte("packages:\n  - packages/*\nminimumReleaseAge: 1440\ntrustPolicy: no-downgrade\nblockExoticSubdeps: true\nstrictDepBuilds: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	workflow := `name: CI
on: [push]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@main
`
	if err := os.WriteFile(workflowPath, []byte(workflow), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func expectFinding(t *testing.T, findings []model.Finding, ruleID string) {
	t.Helper()
	for _, finding := range findings {
		if finding.RuleID == ruleID {
			return
		}
	}
	t.Fatalf("expected finding %s, got %+v", ruleID, findings)
}

func expectNoFinding(t *testing.T, findings []model.Finding, ruleID string) {
	t.Helper()
	for _, finding := range findings {
		if finding.RuleID == ruleID {
			t.Fatalf("did not expect finding %s, got %+v", ruleID, findings)
		}
	}
}
