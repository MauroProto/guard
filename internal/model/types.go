package model

import "time"

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

// Finding represents a single check result.
type Finding struct {
	RuleID      string         `json:"rule_id" yaml:"rule_id"`
	Severity    Severity       `json:"severity" yaml:"severity"`
	Category    string         `json:"category,omitempty" yaml:"category,omitempty"`
	Title       string         `json:"title" yaml:"title"`
	Message     string         `json:"message" yaml:"message"`
	Remediation string         `json:"remediation,omitempty" yaml:"remediation,omitempty"`
	File        string         `json:"file,omitempty" yaml:"file,omitempty"`
	Line        int            `json:"line,omitempty" yaml:"line,omitempty"`
	Blocking    bool           `json:"blocking" yaml:"blocking"`
	Muted       bool           `json:"muted,omitempty" yaml:"muted,omitempty"`
	Command     string         `json:"command,omitempty" yaml:"command,omitempty"`
	Evidence    map[string]any `json:"evidence,omitempty" yaml:"evidence,omitempty"`
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

// HasBlockingFindings returns true if any non-muted finding is blocking.
func (r *Report) HasBlockingFindings() bool {
	for _, f := range r.Findings {
		if f.Blocking && !f.Muted {
			return true
		}
	}
	return false
}
