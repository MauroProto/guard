package policy

import (
	"time"

	"guard/internal/config"
)

// AddPackageException appends a package exception to the config.
func AddPackageException(cfg *config.Config, pkg, reason string, expiry time.Time) {
	cfg.Exceptions.Packages = append(cfg.Exceptions.Packages, config.PackageException{
		Name:      pkg,
		Reason:    reason,
		Allows:    []string{"build_script"},
		ExpiresAt: expiry.Format("2006-01-02"),
	})
}
