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
	FailOn       string
	Scope        string
	Files        []string
	ChangedFiles bool
	Offline      bool
	DisableOSV   bool
	OSVClient    osv.Client
	Now          time.Time
}

// ScanRepo runs all checks against the repository and returns a report.
func ScanRepo(ctx context.Context, root string, cfg *config.Config, opts *ScanOptions) (*model.Report, error) {
	report := NewReport(root)

	targets, err := ResolveScanTargets(cfg, opts)
	if err != nil {
		return nil, err
	}
	if !targets.Any() {
		report.Normalize()
		return report, nil
	}

	var state *repo.State
	if targets.NeedsRepoState() {
		state, err = repo.Inspect(root, cfg.GitHub.WorkflowPaths)
		if err != nil {
			return nil, err
		}
	}

	if targets.RepoStructure || targets.PackageMetadata {
		checkRepo(report, cfg, state, targets)
	}

	if targets.WorkspacePosture || targets.BuildApprovals {
		if state.HasPNPMWorkspace {
			ws, err := pnpm.Load(root)
			if err != nil {
				return nil, fmt.Errorf("load pnpm workspace: %w", err)
			}
			if targets.WorkspacePosture {
				checkWorkspacePosture(report, cfg, ws)
			}
			if targets.BuildApprovals {
				checkPendingBuildApprovals(report, cfg, root, ws)
			}
		} else if targets.WorkspacePosture {
			addFinding(report, cfg, model.Finding{
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
	}

	if targets.WorkflowAudit {
		for _, f := range github.AuditWorkflows(root, selectWorkflowFiles(root, state.WorkflowFiles, targets)) {
			addFinding(report, cfg, f)
		}
	}

	if targets.WorkflowCodeowners && len(state.WorkflowFiles) > 0 && !state.HasCodeowners {
		addFinding(report, cfg, model.Finding{
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

	if targets.PolicyLint {
		for _, finding := range scanPolicy(root, cfg) {
			addFinding(report, cfg, finding)
		}
	}

	if targets.OSV && shouldScanOSV(cfg, opts) {
		client := optsOSVClient(root, opts)
		if client != nil {
			for _, finding := range scanOSV(ctx, root, cfg, client) {
				addFinding(report, cfg, finding)
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

func selectWorkflowFiles(root string, files []string, targets ScanTargets) []string {
	if !targets.WorkflowAudit || len(files) == 0 || targets.WorkflowFiles == nil {
		return files
	}
	selected := make([]string, 0, len(files))
	for _, abs := range files {
		rel, err := filepath.Rel(root, abs)
		if err != nil {
			continue
		}
		if targets.IncludesWorkflowFile(rel) {
			selected = append(selected, abs)
		}
	}
	return selected
}

func scanPolicy(root string, cfg *config.Config) []model.Finding {
	issues := config.Lint(root, cfg)
	findings := make([]model.Finding, 0, len(issues))
	for _, issue := range issues {
		severity := model.SeverityLow
		if issue.Severity == "error" {
			severity = model.SeverityHigh
		}
		findings = append(findings, model.Finding{
			RuleID:      issue.Code,
			Severity:    severity,
			Category:    model.CategoryPolicy,
			Title:       "Guard policy issue",
			Message:     issue.Message,
			Remediation: "Run `guard policy lint` and narrow the field or exception that Guard flagged.",
			File:        filepath.ToSlash(config.DefaultPolicyPath),
			Evidence: map[string]any{
				"path":          issue.Path,
				"lint_severity": issue.Severity,
			},
		})
	}
	return findings
}

func checkRepo(report *model.Report, cfg *config.Config, state *repo.State, targets ScanTargets) {
	if targets.RepoStructure && !state.HasPackageJSON {
		addFinding(report, cfg, model.Finding{
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

	if targets.RepoStructure && cfg.PNPM.RequireLockfile && !state.HasPNPMLockfile {
		addFinding(report, cfg, model.Finding{
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

	if !targets.PackageMetadata {
		return
	}

	for _, pkg := range state.Packages {
		if !targets.IncludesPackageFile(pkg.RelFile) {
			continue
		}
		pkgLabel := packageLabel(pkg)
		pkgEvidence := map[string]any{
			"package":      pkgLabel,
			"version":      pkg.PackageJSON.Version,
			"importer":     pkg.RelDir,
			"package_file": pkg.RelFile,
			"package_dir":  pkg.RelDir,
		}

		if cfg.PNPM.RequirePackageManagerField && pkg.PackageJSON != nil && pkg.PackageJSON.PackageManager == "" {
			addFinding(report, cfg, model.Finding{
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
				addFinding(report, cfg, model.Finding{
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

func checkWorkspacePosture(report *model.Report, cfg *config.Config, ws *pnpm.Workspace) {
	if cfg.PNPM.MinimumReleaseAgeMinutes > 0 && ws.MinimumReleaseAge == 0 {
		addFinding(report, cfg, model.Finding{
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
		addFinding(report, cfg, model.Finding{
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
		addFinding(report, cfg, model.Finding{
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
		addFinding(report, cfg, model.Finding{
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
		addFinding(report, cfg, model.Finding{
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

}

func checkPendingBuildApprovals(report *model.Report, cfg *config.Config, root string, ws *pnpm.Workspace) {
	var lock *lockfile.PNPM
	if loaded, err := lockfile.Load(filepath.Join(root, "pnpm-lock.yaml")); err == nil {
		lock = loaded
	}
	for name, allowed := range ws.AllowBuilds {
		if allowed {
			continue
		}
		refs := lockfile.ResolvePackageRefs(lock, name)
		if len(refs) == 0 {
			addFinding(report, cfg, buildApprovalFinding(name, "", ""))
			continue
		}
		for _, ref := range refs {
			addFinding(report, cfg, buildApprovalFinding(name, ref.Version, ref.Importer))
		}
	}
}

func buildApprovalFinding(name, version, importer string) model.Finding {
	actions := []model.Action{
		model.ManualAction(fmt.Sprintf("Review %s and approve or remove it from allowBuilds.", name)),
	}
	if npm.ValidPackageName(name) {
		argv := []string{"guard", "approve-build", name}
		if importer != "" {
			argv = append(argv, "--importer", importer)
		}
		if version != "" {
			argv = append(argv, "--version", version)
		}
		actions = append([]model.Action{
			model.ExecAction(
				fmt.Sprintf("Approve build scripts for %s.", name),
				argv,
				true,
				false,
			),
		}, actions...)
	}

	evidence := map[string]any{
		"package": name,
		"kind":    "build_script",
	}
	if version != "" {
		evidence["version"] = version
	}
	if importer != "" {
		evidence["importer"] = importer
	}

	message := fmt.Sprintf("allowBuilds contains %q=false.", name)
	if importer != "" || version != "" {
		message = fmt.Sprintf("allowBuilds contains %q=false for importer %q version %q.", name, importer, version)
	}

	return model.Finding{
		RuleID:      "pnpm.allowBuilds.unreviewed",
		Severity:    model.SeverityHigh,
		Category:    model.CategoryPNPM,
		Package:     name,
		Title:       "A package has a pending build approval",
		Message:     message,
		Remediation: "Review the package and approve or remove it.",
		Actions:     actions,
		Evidence:    evidence,
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
