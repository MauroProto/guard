package model

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// Severity levels from RISK_MODEL.
type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Category constants to avoid typos.
const (
	CategoryRepo   = "repo"
	CategoryPNPM   = "pnpm"
	CategoryGitHub = "github"
	CategoryOSV    = "osv"
	CategoryDiff   = "diff"
	CategoryPolicy = "policy"
)

// SeverityRank returns a numeric rank for comparing severities.
func SeverityRank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

// ParseSeverity converts a string to Severity.
func ParseSeverity(s string) Severity {
	switch s {
	case "critical":
		return SeverityCritical
	case "high":
		return SeverityHigh
	case "medium":
		return SeverityMedium
	case "low":
		return SeverityLow
	default:
		return SeverityHigh
	}
}

// ActionType identifies how a remediation should be handled.
type ActionType string

const (
	ActionTypeExec   ActionType = "exec"
	ActionTypeManual ActionType = "manual"
)

// Action represents a structured remediation.
type Action struct {
	Type            ActionType `json:"type" yaml:"type"`
	Argv            []string   `json:"argv,omitempty" yaml:"argv,omitempty"`
	Label           string     `json:"label,omitempty" yaml:"label,omitempty"`
	SafeForAutoFix  bool       `json:"safe_for_auto_fix,omitempty" yaml:"safe_for_auto_fix,omitempty"`
	RequiresNetwork bool       `json:"requires_network,omitempty" yaml:"requires_network,omitempty"`
}

// ExecAction creates a command-based remediation.
func ExecAction(label string, argv []string, safeForAutoFix, requiresNetwork bool) Action {
	return Action{
		Type:            ActionTypeExec,
		Argv:            append([]string(nil), argv...),
		Label:           label,
		SafeForAutoFix:  safeForAutoFix,
		RequiresNetwork: requiresNetwork,
	}
}

// ManualAction creates a non-executable remediation.
func ManualAction(label string) Action {
	return Action{
		Type:  ActionTypeManual,
		Label: label,
	}
}

// CommandString returns a best-effort shell-ish representation of the action.
func (a Action) CommandString() string {
	if len(a.Argv) > 0 {
		parts := make([]string, 0, len(a.Argv))
		for _, arg := range a.Argv {
			parts = append(parts, quoteArg(arg))
		}
		return strings.Join(parts, " ")
	}
	return a.Label
}

func quoteArg(arg string) string {
	if arg == "" {
		return `""`
	}
	if strings.ContainsAny(arg, " \t\n\"'`$&|;<>*?()[]{}!") {
		return strconv.Quote(arg)
	}
	return arg
}

// Finding represents a single check result.
type Finding struct {
	RuleID      string         `json:"rule_id" yaml:"rule_id"`
	Severity    Severity       `json:"severity" yaml:"severity"`
	Category    string         `json:"category,omitempty" yaml:"category,omitempty"`
	Package     string         `json:"package,omitempty" yaml:"package,omitempty"`
	Title       string         `json:"title" yaml:"title"`
	Message     string         `json:"message" yaml:"message"`
	Remediation string         `json:"remediation,omitempty" yaml:"remediation,omitempty"`
	File        string         `json:"file,omitempty" yaml:"file,omitempty"`
	Line        int            `json:"line,omitempty" yaml:"line,omitempty"`
	Blocking    bool           `json:"blocking" yaml:"blocking"`
	Muted       bool           `json:"muted,omitempty" yaml:"muted,omitempty"`
	Command     string         `json:"command,omitempty" yaml:"command,omitempty"`
	Actions     []Action       `json:"actions,omitempty" yaml:"actions,omitempty"`
	Evidence    map[string]any `json:"evidence,omitempty" yaml:"evidence,omitempty"`
}

// LegacyCommand returns the compatibility command string exposed in JSON.
func (f Finding) LegacyCommand() string {
	if f.Command != "" {
		return f.Command
	}
	for _, action := range f.Actions {
		if cmd := action.CommandString(); cmd != "" {
			return cmd
		}
	}
	return ""
}

// PrimaryAction returns the first structured remediation, if any.
func (f Finding) PrimaryAction() *Action {
	if len(f.Actions) == 0 {
		return nil
	}
	return &f.Actions[0]
}

// Normalize backfills legacy compatibility fields.
func (f *Finding) Normalize() {
	if f.Command == "" {
		f.Command = f.LegacyCommand()
	}
	if f.Package == "" && f.Evidence != nil {
		if pkg, ok := f.Evidence["package"].(string); ok {
			f.Package = pkg
		}
	}
}

// MarshalJSON keeps the deprecated command field available for old consumers.
func (f Finding) MarshalJSON() ([]byte, error) {
	type findingAlias Finding
	alias := findingAlias(f)
	if alias.Command == "" {
		alias.Command = f.LegacyCommand()
	}
	if alias.Package == "" && f.Evidence != nil {
		if pkg, ok := f.Evidence["package"].(string); ok {
			alias.Package = pkg
		}
	}
	return json.Marshal(alias)
}

// Summary holds finding counts by severity.
type Summary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

// Report is the top-level output of a scan or CI run.
type Report struct {
	Tool      string    `json:"tool"`
	Version   string    `json:"version"`
	Root      string    `json:"root"`
	Timestamp time.Time `json:"timestamp"`
	Summary   Summary   `json:"summary"`
	Score     int       `json:"score"`
	Decision  string    `json:"decision"`
	Findings  []Finding `json:"findings"`
}

// AddFinding appends a finding and updates the summary counters.
func (r *Report) AddFinding(f Finding) {
	f.Normalize()
	r.Findings = append(r.Findings, f)
	switch f.Severity {
	case SeverityCritical:
		r.Summary.Critical++
	case SeverityHigh:
		r.Summary.High++
	case SeverityMedium:
		r.Summary.Medium++
	default:
		r.Summary.Low++
	}
}

// Normalize ensures compatibility fields are populated.
func (r *Report) Normalize() {
	for i := range r.Findings {
		r.Findings[i].Normalize()
	}
}

// HasBlockingFindings returns true if any non-muted finding is blocking.
func (r *Report) HasBlockingFindings() bool {
	for _, f := range r.Findings {
		if f.Blocking && !f.Muted {
			return true
		}
	}
	return false
}
