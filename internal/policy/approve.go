package policy

import (
	"time"

	"github.com/MauroProto/guard/internal/config"
)

// AddPackageException appends a package exception to the config.
func AddPackageException(cfg *config.Config, pkg, reason string, expiry time.Time) {
	for i := range cfg.Exceptions.Packages {
		if cfg.Exceptions.Packages[i].Name != pkg {
			continue
		}
		cfg.Exceptions.Packages[i].Reason = reason
		cfg.Exceptions.Packages[i].Allows = []string{"build_script"}
		cfg.Exceptions.Packages[i].ExpiresAt = expiry.Format("2006-01-02")
		return
	}

	cfg.Exceptions.Packages = append(cfg.Exceptions.Packages, config.PackageException{
		Name:      pkg,
		Reason:    reason,
		Allows:    []string{"build_script"},
		ExpiresAt: expiry.Format("2006-01-02"),
	})
}
