package policy

import (
	"testing"
	"time"

	"github.com/MauroProto/guard/internal/config"
	"github.com/MauroProto/guard/internal/model"
)

func TestRuleExceptionActive(t *testing.T) {
	now := time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name   string
		ex     config.RuleException
		expect bool
	}{
		{
			name:   "no expiry",
			ex:     config.RuleException{ID: "test", ExpiresAt: ""},
			expect: true,
		},
		{
			name:   "future expiry",
			ex:     config.RuleException{ID: "test", ExpiresAt: "2026-12-31"},
			expect: true,
		},
		{
			name:   "future expiry rfc3339",
			ex:     config.RuleException{ID: "test", ExpiresAt: "2026-12-31T23:59:59Z"},
			expect: true,
		},
		{
			name:   "past expiry",
			ex:     config.RuleException{ID: "test", ExpiresAt: "2026-01-01"},
			expect: false,
		},
		{
			name:   "same day",
			ex:     config.RuleException{ID: "test", ExpiresAt: "2026-04-12"},
			expect: true,
		},
		{
			name:   "invalid date",
			ex:     config.RuleException{ID: "test", ExpiresAt: "not-a-date"},
			expect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RuleExceptionActive(now, tt.ex)
			if got != tt.expect {
				t.Fatalf("expected %v, got %v", tt.expect, got)
			}
		})
	}
}

func TestFilterExceptionsPackageScopeDoesNotMuteOtherKinds(t *testing.T) {
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	cfg := &config.Config{
		Exceptions: config.Exceptions{
			Packages: []config.PackageException{
				{
					Package:    "sharp",
					Name:       "sharp",
					Kind:       "build_script",
					Version:    "1.2.3",
					Importer:   "apps/web",
					RuleID:     "pnpm.allowBuilds.unreviewed",
					Reason:     "approved build",
					ApprovedAt: "2026-04-12T10:00:00Z",
					ExpiresAt:  "2026-10-12T23:59:59Z",
				},
			},
		},
	}

	findings := []model.Finding{
		{
			RuleID:   "pnpm.allowBuilds.unreviewed",
			Severity: model.SeverityHigh,
			Blocking: true,
			Evidence: map[string]any{
				"package":  "sharp",
				"kind":     "build_script",
				"version":  "1.2.3",
				"importer": "apps/web",
			},
		},
		{
			RuleID:   "repo.nodeEngine.missing",
			Severity: model.SeverityLow,
			Blocking: false,
			Evidence: map[string]any{
				"package": "sharp",
			},
		},
	}

	result := FilterExceptions(cfg, findings, now)
	if !result[0].Muted {
		t.Fatal("expected matching build_script finding to be muted")
	}
	if result[1].Muted {
		t.Fatal("did not expect unrelated finding to be muted")
	}
}

func TestFilterExceptionsLegacyAllowsRemainsCompatible(t *testing.T) {
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	cfg := &config.Config{
		Exceptions: config.Exceptions{
			Packages: []config.PackageException{
				{
					Name:      "sharp",
					Allows:    []string{"build_script"},
					ExpiresAt: "2026-10-12",
				},
			},
		},
	}

	findings := []model.Finding{{
		RuleID:   "pnpm.allowBuilds.unreviewed",
		Severity: model.SeverityHigh,
		Blocking: true,
		Evidence: map[string]any{
			"package": "sharp",
			"kind":    "build_script",
		},
	}}

	result := FilterExceptions(cfg, findings, now)
	if !result[0].Muted {
		t.Fatal("expected legacy allows exception to remain compatible")
	}
}

func TestFilterExceptionsMutesActiveException(t *testing.T) {
	now := time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC)
	cfg := &config.Config{
		Exceptions: config.Exceptions{
			Rules: []config.RuleException{
				{ID: "test.rule", Reason: "testing", ExpiresAt: "2026-12-31"},
			},
		},
	}

	findings := []model.Finding{
		{RuleID: "test.rule", Severity: model.SeverityHigh, Blocking: true},
		{RuleID: "other.rule", Severity: model.SeverityMedium},
	}

	result := FilterExceptions(cfg, findings, now)

	// The test.rule finding should be muted
	var mutedCount, policyCount int
	for _, f := range result {
		if f.RuleID == "test.rule" && f.Muted {
			mutedCount++
		}
		if f.RuleID == "policy.exception.expired" {
			policyCount++
		}
	}
	if mutedCount != 1 {
		t.Fatalf("expected 1 muted finding, got %d", mutedCount)
	}
	if policyCount != 0 {
		t.Fatal("expected no expired exception findings")
	}
}

func TestFilterExceptionsExpiredGeneratesFinding(t *testing.T) {
	now := time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC)
	cfg := &config.Config{
		Exceptions: config.Exceptions{
			Rules: []config.RuleException{
				{ID: "test.rule", Reason: "old", ExpiresAt: "2025-01-01"},
			},
		},
	}

	findings := []model.Finding{
		{RuleID: "test.rule", Severity: model.SeverityHigh, Blocking: true},
	}

	result := FilterExceptions(cfg, findings, now)

	var expiredCount int
	for _, f := range result {
		if f.RuleID == "policy.exception.expired" {
			expiredCount++
		}
	}
	if expiredCount != 1 {
		t.Fatalf("expected 1 expired exception finding, got %d", expiredCount)
	}
}

func TestApplyFailOn(t *testing.T) {
	findings := []model.Finding{
		{RuleID: "a", Severity: model.SeverityHigh},
		{RuleID: "b", Severity: model.SeverityMedium},
		{RuleID: "c", Severity: model.SeverityLow},
	}

	ApplyFailOn(findings, model.SeverityHigh)

	if !findings[0].Blocking {
		t.Fatal("high finding should be blocking with failOn=high")
	}
	if findings[1].Blocking {
		t.Fatal("medium finding should not be blocking with failOn=high")
	}
	if findings[2].Blocking {
		t.Fatal("low finding should not be blocking with failOn=high")
	}
}

func TestAddPackageExceptionUpdatesExistingPackage(t *testing.T) {
	cfg := &config.Config{
		Exceptions: config.Exceptions{
			Packages: []config.PackageException{
				{
					Package:   "lodash",
					Name:      "lodash",
					Kind:      "build_script",
					RuleID:    "pnpm.allowBuilds.unreviewed",
					Reason:    "keep",
					Allows:    []string{"build_script"},
					ExpiresAt: "2026-12-31T00:00:00Z",
				},
				{
					Package:   "sharp",
					Name:      "sharp",
					Kind:      "build_script",
					RuleID:    "pnpm.allowBuilds.unreviewed",
					Reason:    "old reason",
					Allows:    []string{"build_script"},
					ExpiresAt: "2026-01-01T00:00:00Z",
				},
			},
		},
	}

	expiry := time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)
	AddPackageException(cfg, PackageApproval{
		Package:    "sharp",
		Kind:       "build_script",
		RuleID:     "pnpm.allowBuilds.unreviewed",
		Reason:     "new reason",
		ApprovedAt: time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC),
		ExpiresAt:  expiry,
	})

	if len(cfg.Exceptions.Packages) != 2 {
		t.Fatalf("expected existing package exception to be updated in place, got %d entries", len(cfg.Exceptions.Packages))
	}

	if cfg.Exceptions.Packages[0].Name != "lodash" {
		t.Fatalf("expected unrelated exception to remain first, got %q", cfg.Exceptions.Packages[0].Name)
	}

	updated := cfg.Exceptions.Packages[1]
	if updated.Package != "sharp" || updated.Name != "sharp" {
		t.Fatalf("expected sharp exception to remain in place, got %+v", updated)
	}
	if updated.Reason != "new reason" {
		t.Fatalf("expected reason to be updated, got %q", updated.Reason)
	}
	if updated.ExpiresAt != "2026-10-12T00:00:00Z" {
		t.Fatalf("expected expiry to be updated, got %q", updated.ExpiresAt)
	}
	if updated.ApprovedAt != "2026-04-12T00:00:00Z" {
		t.Fatalf("expected approvedAt to be updated, got %q", updated.ApprovedAt)
	}
}
