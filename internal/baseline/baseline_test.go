package baseline

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/MauroProto/guard/internal/model"
)

func TestSaveLoadAndFilterFindings(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "baseline.json")
	findings := []model.Finding{
		{RuleID: "repo.lockfile.missing", Severity: model.SeverityHigh, Title: "Missing lockfile", File: "pnpm-lock.yaml"},
		{RuleID: "repo.nodeEngine.missing", Severity: model.SeverityLow, Title: "Missing node engine", File: "package.json"},
	}
	for i := range findings {
		findings[i].Normalize()
	}
	if err := Save(path, findings, time.Unix(1, 0).UTC()); err != nil {
		t.Fatalf("save baseline: %v", err)
	}
	file, err := Load(path)
	if err != nil {
		t.Fatalf("load baseline: %v", err)
	}
	filtered := FilterFindings(findings, file)
	if len(filtered) != 0 {
		t.Fatalf("expected baseline to suppress all findings, got %+v", filtered)
	}
}

func TestBaselineFingerprintIgnoresLineOnlyDrift(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "baseline.json")

	recorded := model.Finding{
		RuleID:   "github.workflow.unpinned_action",
		Severity: model.SeverityHigh,
		Category: model.CategoryGitHub,
		Title:    "Workflow action is not pinned to a full commit SHA",
		File:     ".github/workflows/test.yml",
		Line:     8,
		Evidence: map[string]any{"uses": "actions/checkout@main"},
	}
	recorded.Normalize()
	if err := Save(path, []model.Finding{recorded}, time.Unix(1, 0).UTC()); err != nil {
		t.Fatalf("save baseline: %v", err)
	}

	shifted := recorded
	shifted.Line = 9
	shifted.Fingerprint = ""
	shifted.Normalize()

	file, err := Load(path)
	if err != nil {
		t.Fatalf("load baseline: %v", err)
	}
	filtered := FilterFindings([]model.Finding{shifted}, file)
	if len(filtered) != 0 {
		t.Fatalf("expected line-only drift to stay suppressed, got %+v", filtered)
	}
}
