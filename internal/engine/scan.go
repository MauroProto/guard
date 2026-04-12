package engine

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"guard/internal/config"
	"guard/internal/github"
	"guard/internal/model"
	"guard/internal/pnpm"
	"guard/internal/policy"
	"guard/internal/repo"
)

// ScanOptions holds optional overrides for the scan.
type ScanOptions struct {
	FailOn string
}

// ScanRepo runs all checks against the repository and returns a report.
func ScanRepo(ctx context.Context, root string, cfg *config.Config, opts *ScanOptions) (*model.Report, error) {
	_ = ctx
	report := NewReport(root)

	state, err := repo.Inspect(root)
	if err != nil {
		return nil, err
	}

	// Repo checks
	checkRepo(report, cfg, state)

	// pnpm checks
	if state.HasPNPMWorkspace {
		ws, err := pnpm.Load(root)
		if err != nil {
			return nil, fmt.Errorf("load pnpm workspace: %w", err)
		}
		checkPNPM(report, cfg, ws)
	} else {
		report.AddFinding(model.Finding{
			RuleID:      "pnpm.workspace.missing",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryPNPM,
			Title:       "pnpm-workspace.yaml is missing",
			Message:     "Guard could not find pnpm-workspace.yaml.",
			Remediation: "Create pnpm-workspace.yaml and define your supply chain defaults.",
		})
	}

	// GitHub workflow checks
	workflowFindings := github.AuditWorkflows(root, state.WorkflowFiles)
	for _, f := range workflowFindings {
		report.AddFinding(f)
	}

	if cfg.GitHub.RequireCodeownersForWorkflows && len(state.WorkflowFiles) > 0 && !state.HasCodeowners {
		report.AddFinding(model.Finding{
			RuleID:      "github.workflow.codeowners.missing",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryGitHub,
			Title:       "CODEOWNERS is missing for workflow changes",
			Message:     "The repository has workflows but no CODEOWNERS file.",
			Remediation: "Protect workflow changes with CODEOWNERS review.",
			File:        filepath.ToSlash(".github/CODEOWNERS"),
			Command:     `echo ".github/workflows/ @security-team" > .github/CODEOWNERS`,
		})
	}

	// TODO: integrate OSV when cfg.OSV.Enabled is true.

	// Apply exceptions
	report.Findings = policy.FilterExceptions(cfg, report.Findings, time.Now())

	// Determine fail-on threshold
	failOn := model.ParseSeverity(cfg.Enforcement.FailOn)
	if opts != nil && opts.FailOn != "" {
		failOn = model.ParseSeverity(opts.FailOn)
	}
	policy.ApplyFailOn(report.Findings, failOn)

	// Recalculate summary after filtering
	report.Summary = model.Summary{}
	for _, f := range report.Findings {
		if f.Muted {
			continue
		}
		switch f.Severity {
		case model.SeverityCritical:
			report.Summary.Critical++
		case model.SeverityHigh:
			report.Summary.High++
		case model.SeverityMedium:
			report.Summary.Medium++
		default:
			report.Summary.Low++
		}
	}

	report.Score = score(report.Findings)
	if report.HasBlockingFindings() {
		report.Decision = "fail"
	}

	return report, nil
}

func checkRepo(report *model.Report, cfg *config.Config, state *repo.State) {
	if !state.HasPackageJSON {
		report.AddFinding(model.Finding{
			RuleID:      "repo.package_json.missing",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryRepo,
			Title:       "package.json is missing",
			Message:     "Guard could not find package.json in the repository root.",
			Remediation: "Create package.json or point Guard to the correct repo root.",
			Command:     "pnpm init",
		})
		return
	}

	if cfg.PNPM.RequireLockfile && !state.HasPNPMLockfile {
		report.AddFinding(model.Finding{
			RuleID:      "repo.lockfile.missing",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryRepo,
			Title:       "pnpm lockfile is missing",
			Message:     "pnpm-lock.yaml was not found.",
			Remediation: "Generate and commit the lockfile.",
			Command:     "pnpm install --lockfile-only",
		})
	}

	if cfg.PNPM.RequirePackageManagerField && state.PackageJSON != nil && state.PackageJSON.PackageManager == "" {
		report.AddFinding(model.Finding{
			RuleID:      "repo.packageManager.unpinned",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryRepo,
			Title:       "packageManager field is missing",
			Message:     "package.json does not pin the package manager version.",
			Remediation: "Pin the pnpm version in package.json.",
			Command:     `npm pkg set "packageManager"="pnpm@$(pnpm --version)"`,
		})
	}

	if cfg.PNPM.RequireNodeEngine && state.PackageJSON != nil && len(state.PackageJSON.Engines) == 0 {
		report.AddFinding(model.Finding{
			RuleID:      "repo.nodeEngine.missing",
			Severity:    model.SeverityLow,
			Category:    model.CategoryRepo,
			Title:       "Node engine is not declared",
			Message:     "package.json does not define engines.node.",
			Remediation: "Declare the minimum Node version.",
			Command:     `npm pkg set "engines.node"=">=22"`,
		})
	}
}

func checkPNPM(report *model.Report, cfg *config.Config, ws *pnpm.Workspace) {
	if cfg.PNPM.MinimumReleaseAgeMinutes > 0 && ws.MinimumReleaseAge == 0 {
		report.AddFinding(model.Finding{
			RuleID:      "pnpm.minimumReleaseAge.missing",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryPNPM,
			Title:       "minimumReleaseAge is not configured",
			Message:     "The workspace does not delay newly published releases.",
			Remediation: "Set minimumReleaseAge to at least 1440 minutes.",
			Command:     "guard init --force",
		})
	} else if ws.MinimumReleaseAge > 0 && ws.MinimumReleaseAge < cfg.PNPM.MinimumReleaseAgeMinutes {
		report.AddFinding(model.Finding{
			RuleID:      "pnpm.minimumReleaseAge.too_low",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryPNPM,
			Title:       "minimumReleaseAge is lower than policy",
			Message:     fmt.Sprintf("Workspace value (%d min) is lower than policy (%d min).", ws.MinimumReleaseAge, cfg.PNPM.MinimumReleaseAgeMinutes),
			Remediation: "Raise minimumReleaseAge in pnpm-workspace.yaml.",
			Command:     fmt.Sprintf("guard init --force --minimum-release-age %d", cfg.PNPM.MinimumReleaseAgeMinutes),
			Evidence:    map[string]any{"current": ws.MinimumReleaseAge, "required": cfg.PNPM.MinimumReleaseAgeMinutes},
		})
	}

	if cfg.PNPM.BlockExoticSubdeps && !ws.BlockExoticSubdeps {
		report.AddFinding(model.Finding{
			RuleID:      "pnpm.blockExoticSubdeps.disabled",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryPNPM,
			Title:       "Exotic transitive sources are not blocked",
			Message:     "blockExoticSubdeps is disabled in pnpm-workspace.yaml.",
			Remediation: "Enable blockExoticSubdeps in pnpm-workspace.yaml.",
			Command:     "guard init --force",
		})
	}

	if cfg.PNPM.StrictDepBuilds && !ws.StrictDepBuilds {
		report.AddFinding(model.Finding{
			RuleID:      "pnpm.strictDepBuilds.disabled",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryPNPM,
			Title:       "Dependency build approval is not enforced",
			Message:     "strictDepBuilds is disabled in pnpm-workspace.yaml.",
			Remediation: "Enable strictDepBuilds in pnpm-workspace.yaml.",
			Command:     "guard init --force",
		})
	}

	if cfg.PNPM.TrustPolicy == "no-downgrade" && ws.TrustPolicy != "no-downgrade" {
		report.AddFinding(model.Finding{
			RuleID:      "pnpm.trustPolicy.disabled",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryPNPM,
			Title:       "Trust downgrade protection is not enabled",
			Message:     "trustPolicy is not set to no-downgrade in pnpm-workspace.yaml.",
			Remediation: "Enable trustPolicy: no-downgrade.",
			Command:     "guard init --force",
		})
	}

	for name, allowed := range ws.AllowBuilds {
		if !allowed {
			report.AddFinding(model.Finding{
				RuleID:      "pnpm.allowBuilds.unreviewed",
				Severity:    model.SeverityHigh,
				Category:    model.CategoryPNPM,
				Title:       "A package has a pending build approval",
				Message:     fmt.Sprintf("allowBuilds contains %q=false.", name),
				Remediation: "Review the package and approve or remove it.",
				Command:     "guard approve " + name,
				Evidence:    map[string]any{"package": name},
			})
		}
	}
}

// score computes a risk score from findings. Muted findings do not contribute.
func score(findings []model.Finding) int {
	total := 0
	for _, f := range findings {
		if f.Muted {
			continue
		}
		switch f.Severity {
		case model.SeverityCritical:
			total += 40
		case model.SeverityHigh:
			total += 20
		case model.SeverityMedium:
			total += 8
		default:
			total += 3
		}
	}
	if total > 100 {
		return 100
	}
	return total
}
