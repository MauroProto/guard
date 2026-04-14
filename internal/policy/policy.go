package policy

import (
	"time"

	"github.com/MauroProto/guard/internal/config"
	"github.com/MauroProto/guard/internal/model"
)

// RuleExceptionActive returns true if the exception has not expired.
func RuleExceptionActive(now time.Time, ex config.RuleException) bool {
	return exceptionActive(now, ex.ExpiresAt)
}

// PackageExceptionActive returns true if the package exception has not expired.
func PackageExceptionActive(now time.Time, ex config.PackageException) bool {
	return exceptionActive(now, ex.ExpiresAt)
}

// FilterExceptions applies rule and package exceptions to findings.
// Active exceptions mute findings. Expired exceptions generate new findings.
func FilterExceptions(cfg *config.Config, findings []model.Finding, now time.Time) []model.Finding {
	var result []model.Finding

	for i := range findings {
		f := findings[i]
		muted := false

		// Check rule exceptions
		for _, ex := range cfg.Exceptions.Rules {
			if ex.ID == f.RuleID {
				if RuleExceptionActive(now, ex) {
					f.Muted = true
					f.Blocking = false
					muted = true
				} else {
					result = append(result, model.Finding{
						RuleID:      "policy.exception.expired",
						Severity:    model.SeverityHigh,
						Category:    model.CategoryPolicy,
						Title:       "Rule exception has expired",
						Message:     "Exception for " + ex.ID + " expired on " + ex.ExpiresAt + ". Reason: " + ex.Reason,
						Remediation: "Remove the exception or set a new expiration date.",
						Blocking:    true,
					})
				}
				break
			}
		}

		// Check package exceptions with scoped matching.
		if !muted {
			for _, ex := range cfg.Exceptions.Packages {
				if !matchesPackageException(ex, f) {
					continue
				}
				if PackageExceptionActive(now, ex) {
					f.Muted = true
					f.Blocking = false
				} else {
					result = append(result, model.Finding{
						RuleID:      "policy.exception.expired",
						Severity:    model.SeverityHigh,
						Category:    model.CategoryPolicy,
						Title:       "Package exception has expired",
						Message:     "Exception for package " + packageExceptionName(ex) + " expired on " + ex.ExpiresAt + ".",
						Remediation: "Remove the exception or set a new expiration date.",
						Blocking:    true,
					})
				}
				break
			}
		}

		result = append(result, f)
	}

	return result
}

func exceptionActive(now time.Time, expiresAt string) bool {
	if expiresAt == "" {
		return true
	}
	if t, err := time.Parse(time.RFC3339, expiresAt); err == nil {
		return now.Before(t) || now.Equal(t)
	}
	t, err := time.Parse("2006-01-02", expiresAt)
	if err != nil {
		return false
	}
	// Legacy date-only exceptions stay active until the end of the specified day.
	return now.Before(t.Add(24*time.Hour)) || now.Equal(t.Add(24*time.Hour))
}

func matchesPackageException(ex config.PackageException, f model.Finding) bool {
	if f.Evidence == nil {
		return false
	}
	if pkg := packageExceptionName(ex); pkg != "" && evidenceString(f.Evidence, "package") != pkg {
		return false
	}
	if kind := packageExceptionKind(ex); kind != "" && evidenceString(f.Evidence, "kind") != kind {
		return false
	}
	if ex.Version != "" && evidenceString(f.Evidence, "version") != ex.Version {
		return false
	}
	if ex.Importer != "" && evidenceString(f.Evidence, "importer") != ex.Importer {
		return false
	}
	if ex.RuleID != "" && f.RuleID != ex.RuleID {
		return false
	}
	return packageExceptionName(ex) != ""
}

func packageExceptionName(ex config.PackageException) string {
	if ex.Package != "" {
		return ex.Package
	}
	return ex.Name
}

func packageExceptionKind(ex config.PackageException) string {
	if ex.Kind != "" {
		return ex.Kind
	}
	for _, allowed := range ex.Allows {
		if allowed == "build_script" {
			return "build_script"
		}
	}
	return ""
}

func evidenceString(evidence map[string]any, key string) string {
	if evidence == nil {
		return ""
	}
	if value, ok := evidence[key].(string); ok {
		return value
	}
	return ""
}

// ApplyFailOn sets Blocking=true for all non-muted findings at or above the threshold.
func ApplyFailOn(findings []model.Finding, failOn model.Severity) {
	threshold := model.SeverityRank(failOn)
	for i := range findings {
		if findings[i].Muted {
			continue
		}
		if model.SeverityRank(findings[i].Severity) >= threshold {
			findings[i].Blocking = true
		}
	}
}
