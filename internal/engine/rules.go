package engine

import (
	"github.com/MauroProto/guard/internal/config"
	"github.com/MauroProto/guard/internal/model"
	"github.com/MauroProto/guard/internal/rules"
)

type RuleSpec struct {
	ID              string
	DefaultSeverity model.Severity
	Enabled         func(*config.Config) bool
}

var ruleRegistry = map[string]RuleSpec{
	"github.workflow.unpinned_action": {
		ID:              "github.workflow.unpinned_action",
		DefaultSeverity: model.SeverityHigh,
		Enabled: func(cfg *config.Config) bool {
			return cfg == nil || cfg.GitHub.RequirePinnedActions
		},
	},
	"github.workflow.permissions.missing": {
		ID:              "github.workflow.permissions.missing",
		DefaultSeverity: model.SeverityMedium,
		Enabled: func(cfg *config.Config) bool {
			return cfg == nil || cfg.GitHub.RequireReadOnlyDefaultToken
		},
	},
	"github.workflow.token_permissions.broad": {
		ID:              "github.workflow.token_permissions.broad",
		DefaultSeverity: model.SeverityHigh,
		Enabled: func(cfg *config.Config) bool {
			return cfg == nil || cfg.GitHub.RequireReadOnlyDefaultToken
		},
	},
	"github.workflow.job_permissions.broad": {
		ID:              "github.workflow.job_permissions.broad",
		DefaultSeverity: model.SeverityHigh,
		Enabled: func(cfg *config.Config) bool {
			return cfg == nil || cfg.GitHub.RequireReadOnlyDefaultToken
		},
	},
}

func addFinding(report *model.Report, cfg *config.Config, finding model.Finding) {
	if spec, ok := ruleRegistry[finding.RuleID]; ok && spec.Enabled != nil && !spec.Enabled(cfg) {
		return
	}
	rules.ApplyDefaults(&finding)
	report.AddFinding(finding)
}
