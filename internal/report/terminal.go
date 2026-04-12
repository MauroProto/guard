package report

import (
	"fmt"
	"sort"
	"strings"

	"guard/internal/model"
)

// color codes
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorGreen  = "\033[32m"
	colorCyan   = "\033[36m"
	colorDim    = "\033[2m"
	colorBold   = "\033[1m"
)

// Terminal renders a human-readable report. Set noColor to disable ANSI escapes.
func Terminal(r *model.Report, noColor bool) string {
	c := colorizer(noColor)
	var b strings.Builder

	fmt.Fprintf(&b, "%sGuard %s%s\n", c(colorBold), r.Version, c(colorReset))
	fmt.Fprintf(&b, "Root: %s\n", r.Root)

	decColor := colorGreen
	if r.Decision == "fail" {
		decColor = colorRed
	}
	fmt.Fprintf(&b, "Decision: %s%s%s\n", c(decColor), strings.ToUpper(r.Decision), c(colorReset))
	fmt.Fprintf(&b, "Score: %d/100\n", r.Score)
	fmt.Fprintf(&b, "Summary: critical=%d high=%d medium=%d low=%d\n",
		r.Summary.Critical, r.Summary.High, r.Summary.Medium, r.Summary.Low)

	if len(r.Findings) == 0 {
		b.WriteString(fmt.Sprintf("\n%sNo findings.%s\n", c(colorGreen), c(colorReset)))
		return b.String()
	}

	// Sort by severity (critical first)
	sorted := make([]model.Finding, len(r.Findings))
	copy(sorted, r.Findings)
	sort.Slice(sorted, func(i, j int) bool {
		return model.SeverityRank(sorted[i].Severity) > model.SeverityRank(sorted[j].Severity)
	})

	// Count blocking
	blocking := 0
	warnings := 0
	muted := 0
	for _, f := range sorted {
		if f.Muted {
			muted++
		} else if f.Blocking {
			blocking++
		} else {
			warnings++
		}
	}
	fmt.Fprintf(&b, "\n%d blocking, %d warnings, %d muted\n\n", blocking, warnings, muted)

	b.WriteString("Findings:\n")
	for _, f := range sorted {
		sevColor := severityColor(f.Severity)
		prefix := ""
		suffix := ""
		if f.Muted {
			prefix = c(colorDim)
			suffix = " [MUTED]" + c(colorReset)
		}
		fmt.Fprintf(&b, "%s  %s[%s]%s %s (%s)%s\n",
			prefix, c(sevColor), strings.ToUpper(string(f.Severity)), c(colorReset),
			f.Title, f.RuleID, suffix)
		fmt.Fprintf(&b, "%s    %s%s\n", prefix, f.Message, suffix)
		if f.File != "" {
			loc := f.File
			if f.Line > 0 {
				loc = fmt.Sprintf("%s:%d", f.File, f.Line)
			}
			fmt.Fprintf(&b, "%s    File: %s%s\n", prefix, loc, suffix)
		}
		if f.Remediation != "" {
			fmt.Fprintf(&b, "%s    Fix: %s%s\n", prefix, f.Remediation, suffix)
		}
	}

	return b.String()
}

func severityColor(s model.Severity) string {
	switch s {
	case model.SeverityCritical:
		return colorRed
	case model.SeverityHigh:
		return colorRed
	case model.SeverityMedium:
		return colorYellow
	default:
		return colorCyan
	}
}

func colorizer(noColor bool) func(string) string {
	if noColor {
		return func(string) string { return "" }
	}
	return func(code string) string { return code }
}
