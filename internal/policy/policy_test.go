package policy

import (
	"testing"
	"time"

	"guard/internal/config"
	"guard/internal/model"
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
