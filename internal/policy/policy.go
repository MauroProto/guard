package policy

import (
	"time"

	"github.com/MauroProto/guard/internal/config"
	"github.com/MauroProto/guard/internal/model"
)

// RuleExceptionActive returns true if the exception has not expired.
func RuleExceptionActive(now time.Time, ex config.RuleException) bool {
	if ex.ExpiresAt == "" {
		return true
	}
	t, err := time.Parse("2006-01-02", ex.ExpiresAt)
	if err != nil {
		return false
	}
	return now.Before(t) || now.Equal(t)
}

// PackageExceptionActive returns true if the package exception has not expired.
func PackageExceptionActive(now time.Time, ex config.PackageException) bool {
	if ex.ExpiresAt == "" {
		return true
	}
	t, err := time.Parse("2006-01-02", ex.ExpiresAt)
	if err != nil {
		return false
	}
	return now.Before(t) || now.Equal(t)
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

		// Check package exceptions (using Evidence["package"] if present)
		if !muted {
			if pkgName, ok := f.Evidence["package"].(string); ok {
				for _, ex := range cfg.Exceptions.Packages {
					if ex.Name == pkgName {
						if PackageExceptionActive(now, ex) {
							f.Muted = true
							f.Blocking = false
						} else {
							result = append(result, model.Finding{
								RuleID:      "policy.exception.expired",
								Severity:    model.SeverityHigh,
								Category:    model.CategoryPolicy,
								Title:       "Package exception has expired",
								Message:     "Exception for package " + ex.Name + " expired on " + ex.ExpiresAt + ".",
								Remediation: "Remove the exception or set a new expiration date.",
								Blocking:    true,
							})
						}
						break
					}
				}
			}
		}

		result = append(result, f)
	}

	return result
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
