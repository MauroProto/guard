package policy

import (
	"time"

	"github.com/MauroProto/guard/internal/config"
)

type PackageApproval struct {
	Package    string
	Kind       string
	Version    string
	Importer   string
	RuleID     string
	Reason     string
	ApprovedBy string
	ApprovedAt time.Time
	ExpiresAt  time.Time
}

// AddPackageException upserts a scoped package exception into the config.
func AddPackageException(cfg *config.Config, approval PackageApproval) {
	if approval.Kind == "" {
		approval.Kind = "build_script"
	}
	if approval.RuleID == "" {
		approval.RuleID = "pnpm.allowBuilds.unreviewed"
	}
	if approval.ApprovedAt.IsZero() {
		approval.ApprovedAt = time.Now().UTC()
	}
	if approval.ExpiresAt.IsZero() {
		approval.ExpiresAt = approval.ApprovedAt.AddDate(0, 6, 0)
	}

	for i := range cfg.Exceptions.Packages {
		existing := cfg.Exceptions.Packages[i]
		if packageExceptionName(existing) != approval.Package || packageExceptionKind(existing) != approval.Kind || existing.RuleID != approval.RuleID || existing.Importer != approval.Importer || existing.Version != approval.Version {
			continue
		}
		cfg.Exceptions.Packages[i].Package = approval.Package
		cfg.Exceptions.Packages[i].Name = approval.Package
		cfg.Exceptions.Packages[i].Kind = approval.Kind
		cfg.Exceptions.Packages[i].Version = approval.Version
		cfg.Exceptions.Packages[i].Importer = approval.Importer
		cfg.Exceptions.Packages[i].RuleID = approval.RuleID
		cfg.Exceptions.Packages[i].Reason = approval.Reason
		cfg.Exceptions.Packages[i].ApprovedBy = approval.ApprovedBy
		cfg.Exceptions.Packages[i].ApprovedAt = approval.ApprovedAt.UTC().Format(time.RFC3339)
		cfg.Exceptions.Packages[i].Allows = []string{"build_script"}
		cfg.Exceptions.Packages[i].ExpiresAt = approval.ExpiresAt.UTC().Format(time.RFC3339)
		return
	}

	cfg.Exceptions.Packages = append(cfg.Exceptions.Packages, config.PackageException{
		Package:    approval.Package,
		Name:       approval.Package,
		Kind:       approval.Kind,
		Version:    approval.Version,
		Importer:   approval.Importer,
		RuleID:     approval.RuleID,
		Reason:     approval.Reason,
		ApprovedBy: approval.ApprovedBy,
		ApprovedAt: approval.ApprovedAt.UTC().Format(time.RFC3339),
		Allows:     []string{"build_script"},
		ExpiresAt:  approval.ExpiresAt.UTC().Format(time.RFC3339),
	})
}
