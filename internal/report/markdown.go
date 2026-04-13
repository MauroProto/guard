package report

import (
	"fmt"
	"strings"

	"github.com/MauroProto/guard/internal/model"
)

// Markdown renders a report as a GitHub-flavored Markdown table.
func Markdown(r *model.Report) string {
	var b strings.Builder

	fmt.Fprintf(&b, "## Guard Scan Report\n\n")
	fmt.Fprintf(&b, "**Decision:** %s | **Score:** %d/100\n\n", strings.ToUpper(r.Decision), r.Score)
	fmt.Fprintf(&b, "**Summary:** critical=%d high=%d medium=%d low=%d\n\n",
		r.Summary.Critical, r.Summary.High, r.Summary.Medium, r.Summary.Low)

	if len(r.Findings) == 0 {
		b.WriteString("No findings.\n")
		return b.String()
	}

	b.WriteString("### Findings\n\n")
	b.WriteString("| Severity | Rule | Title | Blocking | File |\n")
	b.WriteString("|----------|------|-------|----------|------|\n")

	for _, f := range r.Findings {
		blocking := ""
		if f.Muted {
			blocking = "Muted"
		} else if f.Blocking {
			blocking = "Yes"
		} else {
			blocking = "No"
		}
		file := f.File
		if file == "" {
			file = "-"
		}
		if f.Line > 0 {
			file = fmt.Sprintf("%s:%d", file, f.Line)
		}
		fmt.Fprintf(&b, "| %s | `%s` | %s | %s | %s |\n",
			strings.ToUpper(string(f.Severity)), f.RuleID, f.Title, blocking, file)
	}

	// Remediation section
	hasRemediation := false
	for _, f := range r.Findings {
		if f.Remediation != "" && !f.Muted {
			if !hasRemediation {
				b.WriteString("\n### Remediation\n\n")
				hasRemediation = true
			}
			fmt.Fprintf(&b, "- **%s**: %s\n", f.RuleID, f.Remediation)
		}
	}

	return b.String()
}
