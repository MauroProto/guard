package review

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/MauroProto/guard/internal/model"
)

func JSON(result *Result) ([]byte, error) {
	clone := *result
	if clone.ChangedPackages == nil {
		clone.ChangedPackages = []string{}
	}
	if clone.PackageReviews == nil {
		clone.PackageReviews = []PackageReview{}
	}
	if clone.WorkflowFindings == nil {
		clone.WorkflowFindings = []model.Finding{}
	}
	if clone.Findings == nil {
		clone.Findings = []model.Finding{}
	}
	return json.MarshalIndent(&clone, "", "  ")
}

func Markdown(result *Result) string {
	var b strings.Builder
	fmt.Fprintf(&b, "## Guard PR Review\n\n")
	fmt.Fprintf(&b, "**Decision:** %s\n\n", strings.ToUpper(result.Decision))
	fmt.Fprintf(&b, "**Base:** `%s`  \n**Head:** `%s`\n\n", result.Base, result.Head)
	fmt.Fprintf(&b, "**Summary:** %s\n\n", result.Summary)

	if len(result.ChangedPackages) > 0 {
		b.WriteString("### Changed Packages\n\n")
		for _, pkg := range result.ChangedPackages {
			fmt.Fprintf(&b, "- `%s`\n", pkg)
		}
		b.WriteString("\n")
	}

	if len(result.PackageReviews) > 0 {
		b.WriteString("### Package Reviews\n\n")
		b.WriteString("| Package | From | To | Importers | Semver | Risk | Trust Δ |\n")
		b.WriteString("|---------|------|----|-----------|--------|------|---------|\n")
		for _, review := range result.PackageReviews {
			delta := review.TrustScoreAfter - review.TrustScoreBefore
			fmt.Fprintf(&b, "| `%s` | `%s` | `%s` | `%s` | `%s` | %d | %d |\n",
				review.Package,
				orDash(review.From),
				orDash(review.To),
				strings.Join(review.Importers, ", "),
				review.SemverChange,
				review.RiskScore,
				delta,
			)
		}
		b.WriteString("\n")
	}

	if len(result.Findings) == 0 {
		b.WriteString("No findings.\n")
		return b.String()
	}

	b.WriteString("### Findings\n\n")
	b.WriteString("| Severity | Rule | Confidence | Title |\n")
	b.WriteString("|----------|------|------------|-------|\n")
	for _, finding := range result.Findings {
		fmt.Fprintf(&b, "| %s | `%s` | %.2f | %s |\n",
			strings.ToUpper(string(finding.Severity)),
			finding.RuleID,
			finding.Confidence,
			finding.Title,
		)
	}
	return b.String()
}

func Terminal(result *Result) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Guard %s review-pr\n", result.Version)
	fmt.Fprintf(&b, "Base: %s\nHead: %s\n", result.Base, result.Head)
	fmt.Fprintf(&b, "Decision: %s\n", strings.ToUpper(result.Decision))
	fmt.Fprintf(&b, "Summary: %s\n", result.Summary)
	if len(result.ChangedPackages) > 0 {
		fmt.Fprintf(&b, "Changed packages: %s\n", strings.Join(result.ChangedPackages, ", "))
	}
	if len(result.Findings) == 0 {
		b.WriteString("\nNo findings.\n")
		return b.String()
	}
	b.WriteString("\nFindings:\n")
	for _, finding := range result.Findings {
		fmt.Fprintf(&b, "  [%s] %s (%s, confidence %.2f)\n", strings.ToUpper(string(finding.Severity)), finding.Title, finding.RuleID, finding.Confidence)
		fmt.Fprintf(&b, "    %s\n", finding.Message)
		if finding.File != "" {
			fmt.Fprintf(&b, "    File: %s\n", finding.File)
		}
	}
	return b.String()
}

func orDash(v string) string {
	if v == "" {
		return "-"
	}
	return v
}
