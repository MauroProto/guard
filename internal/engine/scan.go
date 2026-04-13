package engine

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/MauroProto/guard/internal/config"
	"github.com/MauroProto/guard/internal/github"
	"github.com/MauroProto/guard/internal/lockfile"
	"github.com/MauroProto/guard/internal/model"
	"github.com/MauroProto/guard/internal/npm"
	"github.com/MauroProto/guard/internal/osv"
	"github.com/MauroProto/guard/internal/pnpm"
	"github.com/MauroProto/guard/internal/policy"
	"github.com/MauroProto/guard/internal/repo"
)

// ScanOptions holds optional overrides for the scan.
type ScanOptions struct {
	FailOn     string
	Offline    bool
	DisableOSV bool
	OSVClient  osv.Client
	Now        time.Time
}

// ScanRepo runs all checks against the repository and returns a report.
func ScanRepo(ctx context.Context, root string, cfg *config.Config, opts *ScanOptions) (*model.Report, error) {
	report := NewReport(root)

	state, err := repo.Inspect(root)
	if err != nil {
		return nil, err
	}

	checkRepo(report, cfg, state)

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
			Actions: []model.Action{
				model.ManualAction("Create pnpm-workspace.yaml with your workspace package globs and security defaults."),
			},
		})
	}

	for _, f := range github.AuditWorkflows(root, state.WorkflowFiles) {
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
			Actions: []model.Action{
				model.ManualAction("Add a CODEOWNERS entry for .github/workflows/ and require review on workflow changes."),
			},
		})
	}

	if shouldScanOSV(cfg, opts) {
		client := optsOSVClient(root, opts)
		if client != nil {
			for _, finding := range scanOSV(ctx, root, cfg, client) {
				report.AddFinding(finding)
			}
		}
	}

	now := time.Now()
	if opts != nil && !opts.Now.IsZero() {
		now = opts.Now
	}
	report.Findings = policy.FilterExceptions(cfg, report.Findings, now)

	failOn := model.ParseSeverity(cfg.Enforcement.FailOn)
	if opts != nil && opts.FailOn != "" {
		failOn = model.ParseSeverity(opts.FailOn)
	}
	policy.ApplyFailOn(report.Findings, failOn)

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
	report.Normalize()

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
			File:        "package.json",
			Actions: []model.Action{
				model.ExecAction("Initialize a root package.json.", []string{"pnpm", "init"}, true, false),
			},
		})
	}

	if cfg.PNPM.RequireLockfile && !state.HasPNPMLockfile {
		report.AddFinding(model.Finding{
			RuleID:      "repo.lockfile.missing",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryRepo,
			Title:       "pnpm lockfile is missing",
			Message:     "pnpm-lock.yaml was not found.",
			Remediation: "Generate and commit the lockfile.",
			File:        "pnpm-lock.yaml",
			Actions: []model.Action{
				model.ExecAction("Generate pnpm-lock.yaml.", []string{"pnpm", "install", "--lockfile-only"}, true, true),
			},
		})
	}

	for _, pkg := range state.Packages {
		pkgLabel := packageLabel(pkg)
		pkgEvidence := map[string]any{
			"package":      pkgLabel,
			"package_file": pkg.RelFile,
			"package_dir":  pkg.RelDir,
		}

		if cfg.PNPM.RequirePackageManagerField && pkg.PackageJSON != nil && pkg.PackageJSON.PackageManager == "" {
			report.AddFinding(model.Finding{
				RuleID:      "repo.packageManager.unpinned",
				Severity:    model.SeverityMedium,
				Category:    model.CategoryRepo,
				Package:     pkgLabel,
				Title:       "packageManager field is missing",
				Message:     fmt.Sprintf("%s does not pin the pnpm version in packageManager.", pkg.RelFile),
				Remediation: "Set packageManager to the pnpm version used by the repository.",
				File:        pkg.RelFile,
				Actions: []model.Action{
					model.ManualAction(fmt.Sprintf("Set packageManager in %s.", pkg.RelFile)),
				},
				Evidence: pkgEvidence,
			})
		}

		if cfg.PNPM.RequireNodeEngine && pkg.PackageJSON != nil {
			_, hasNode := pkg.PackageJSON.Engines["node"]
			if !hasNode {
				report.AddFinding(model.Finding{
					RuleID:      "repo.nodeEngine.missing",
					Severity:    model.SeverityLow,
					Category:    model.CategoryRepo,
					Package:     pkgLabel,
					Title:       "Node engine is not declared",
					Message:     fmt.Sprintf("%s does not define engines.node.", pkg.RelFile),
					Remediation: "Declare the minimum supported Node version.",
					File:        pkg.RelFile,
					Actions: []model.Action{
						model.ManualAction(fmt.Sprintf("Set engines.node in %s.", pkg.RelFile)),
					},
					Evidence: pkgEvidence,
				})
			}
		}
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
			Actions: []model.Action{
				model.ManualAction("Set minimumReleaseAge in pnpm-workspace.yaml."),
			},
		})
	} else if ws.MinimumReleaseAge > 0 && ws.MinimumReleaseAge < cfg.PNPM.MinimumReleaseAgeMinutes {
		report.AddFinding(model.Finding{
			RuleID:      "pnpm.minimumReleaseAge.too_low",
			Severity:    model.SeverityMedium,
			Category:    model.CategoryPNPM,
			Title:       "minimumReleaseAge is lower than policy",
			Message:     fmt.Sprintf("Workspace value (%d min) is lower than policy (%d min).", ws.MinimumReleaseAge, cfg.PNPM.MinimumReleaseAgeMinutes),
			Remediation: "Raise minimumReleaseAge in pnpm-workspace.yaml.",
			Actions: []model.Action{
				model.ManualAction("Raise minimumReleaseAge in pnpm-workspace.yaml."),
			},
			Evidence: map[string]any{"current": ws.MinimumReleaseAge, "required": cfg.PNPM.MinimumReleaseAgeMinutes},
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
			Actions: []model.Action{
				model.ManualAction("Enable blockExoticSubdeps in pnpm-workspace.yaml."),
			},
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
			Actions: []model.Action{
				model.ManualAction("Enable strictDepBuilds in pnpm-workspace.yaml."),
			},
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
			Actions: []model.Action{
				model.ManualAction("Set trustPolicy: no-downgrade in pnpm-workspace.yaml."),
			},
		})
	}

	for name, allowed := range ws.AllowBuilds {
		if allowed {
			continue
		}
		actions := []model.Action{
			model.ManualAction(fmt.Sprintf("Review %s and approve or remove it from allowBuilds.", name)),
		}
		if npm.ValidPackageName(name) {
			actions = append([]model.Action{
				model.ExecAction(
					fmt.Sprintf("Approve build scripts for %s.", name),
					[]string{"guard", "approve-build", name},
					true,
					false,
				),
			}, actions...)
		}
		report.AddFinding(model.Finding{
			RuleID:      "pnpm.allowBuilds.unreviewed",
			Severity:    model.SeverityHigh,
			Category:    model.CategoryPNPM,
			Package:     name,
			Title:       "A package has a pending build approval",
			Message:     fmt.Sprintf("allowBuilds contains %q=false.", name),
			Remediation: "Review the package and approve or remove it.",
			Actions:     actions,
			Evidence:    map[string]any{"package": name},
		})
	}
}

func shouldScanOSV(cfg *config.Config, opts *ScanOptions) bool {
	if cfg == nil || !cfg.OSV.Enabled {
		return false
	}
	return opts == nil || !opts.DisableOSV
}

func optsOSVClient(root string, opts *ScanOptions) osv.Client {
	if opts != nil && opts.OSVClient != nil {
		return opts.OSVClient
	}
	offline := opts != nil && opts.Offline
	return osv.NewClient(root, offline)
}

func scanOSV(ctx context.Context, root string, cfg *config.Config, client osv.Client) []model.Finding {
	lock, err := lockfile.Load(filepath.Join(root, "pnpm-lock.yaml"))
	if err != nil {
		return nil
	}

	seen := map[string]bool{}
	var findings []model.Finding
	for key := range lock.Packages {
		name, version, ok := parsePackageKey(key)
		if !ok {
			continue
		}
		dedupeKey := name + "@" + version
		if seen[dedupeKey] {
			continue
		}
		seen[dedupeKey] = true

		advisories, queryErr := client.Query(ctx, osv.Query{
			Name:      name,
			Version:   version,
			Ecosystem: "npm",
		})
		if queryErr != nil {
			continue
		}
		for _, advisory := range advisories {
			findings = append(findings, model.Finding{
				RuleID:      "osv.vulnerability",
				Severity:    advisorySeverity(advisory.Severity, cfg.OSV.FailOnSeverity),
				Category:    model.CategoryOSV,
				Package:     name,
				Title:       "Known vulnerability in dependency",
				Message:     fmt.Sprintf("%s affects %s@%s: %s", advisory.ID, name, version, advisory.Summary),
				Remediation: "Upgrade the dependency to a patched version or document a temporary exception.",
				File:        "pnpm-lock.yaml",
				Actions: []model.Action{
					model.ManualAction(fmt.Sprintf("Review %s@%s against advisory %s.", name, version, advisory.ID)),
				},
				Evidence: map[string]any{
					"package":     name,
					"version":     version,
					"advisory_id": advisory.ID,
				},
			})
		}
	}
	return findings
}

func parsePackageKey(key string) (string, string, bool) {
	key = strings.TrimPrefix(key, "/")
	if idx := strings.Index(key, "("); idx >= 0 {
		key = key[:idx]
	}
	at := strings.LastIndex(key, "@")
	if at <= 0 || at == len(key)-1 {
		return "", "", false
	}
	return key[:at], key[at+1:], true
}

func advisorySeverity(raw, fallback string) model.Severity {
	switch strings.ToLower(raw) {
	case "critical":
		return model.SeverityCritical
	case "high":
		return model.SeverityHigh
	case "medium", "moderate":
		return model.SeverityMedium
	case "low":
		return model.SeverityLow
	default:
		if fallback != "" {
			return model.ParseSeverity(strings.ToLower(fallback))
		}
		return model.SeverityHigh
	}
}

func packageLabel(pkg repo.PackageState) string {
	if pkg.PackageJSON != nil && pkg.PackageJSON.Name != "" {
		return pkg.PackageJSON.Name
	}
	if pkg.RelDir == "." {
		return "root"
	}
	return pkg.RelDir
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
