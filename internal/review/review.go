package review

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/MauroProto/guard/internal/baseline"
	"github.com/MauroProto/guard/internal/config"
	"github.com/MauroProto/guard/internal/diff"
	"github.com/MauroProto/guard/internal/engine"
	"github.com/MauroProto/guard/internal/gitutil"
	"github.com/MauroProto/guard/internal/lockfile"
	"github.com/MauroProto/guard/internal/model"
	"github.com/MauroProto/guard/internal/npm"
	"github.com/MauroProto/guard/internal/osv"
	"github.com/MauroProto/guard/internal/policy"
	"github.com/MauroProto/guard/internal/rules"
)

type Options struct {
	Base           string
	Head           string
	ConfigPath     string
	IgnoreBaseline bool
	Offline        bool
	DisableOSV     bool
	Registry       npm.Registry
	OSVClient      osv.Client
	LoadPackage    func(ctx context.Context, root, name, version string) (*diff.PackageContents, error)
	Now            time.Time
}

type Result struct {
	SchemaVersion    string          `json:"schemaVersion"`
	Tool             string          `json:"tool"`
	Version          string          `json:"version"`
	Base             string          `json:"base"`
	Head             string          `json:"head"`
	Decision         string          `json:"decision"`
	Summary          string          `json:"summary"`
	ChangedPackages  []string        `json:"changedPackages"`
	PackageReviews   []PackageReview `json:"packageReviews"`
	WorkflowFindings []model.Finding `json:"workflowFindings"`
	Findings         []model.Finding `json:"findings"`
}

type PackageReview struct {
	Package          string         `json:"package"`
	From             string         `json:"from,omitempty"`
	To               string         `json:"to"`
	Importers        []string       `json:"importers"`
	SemverChange     string         `json:"semverChange"`
	RiskScore        int            `json:"riskScore"`
	TrustScoreBefore int            `json:"trustScoreBefore"`
	TrustScoreAfter  int            `json:"trustScoreAfter"`
	TrustRegression  bool           `json:"trustRegression"`
	Signals          []diff.Signal  `json:"signals"`
	Advisories       []osv.Advisory `json:"advisories"`
}

type TrustProfile struct {
	RegistryHost          string
	Publisher             string
	Provenance            bool
	TrustedPublishing     bool
	HasInstallScripts     bool
	HasBin                bool
	ReleaseAge            int
	ReleaseCadence        int
	ExceptionHistoryCount int
	HasSignatures         bool
}

type packageChange struct {
	Package   string
	From      string
	To        string
	Importers []string
}

func RunPRReview(ctx context.Context, root string, opts Options) (*Result, error) {
	head := opts.Head
	if head == "" {
		head = "HEAD"
	}
	base := opts.Base
	if base == "" {
		resolved, err := gitutil.ResolveDefaultBase(ctx, root, head)
		if err != nil {
			return nil, err
		}
		base = resolved
	}

	changedFiles, err := gitutil.ChangedFiles(ctx, root, base, head)
	if err != nil {
		return nil, err
	}

	headRoot, err := os.MkdirTemp("", "guard-review-head-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(headRoot)
	if err := gitutil.ExportTree(ctx, root, head, headRoot); err != nil {
		return nil, err
	}

	cfgPath := opts.ConfigPath
	if cfgPath != "" && !filepath.IsAbs(cfgPath) {
		cfgPath = filepath.Join(headRoot, filepath.FromSlash(cfgPath))
	}
	cfg, err := config.Load(headRoot, cfgPath)
	if err != nil {
		return nil, err
	}

	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}

	scanReport, err := engine.ScanRepo(ctx, headRoot, cfg, &engine.ScanOptions{
		Offline:    opts.Offline,
		DisableOSV: true,
		Now:        now,
	})
	if err != nil {
		return nil, err
	}

	workflowFiles := filterWorkflowFiles(changedFiles, cfg.GitHub.WorkflowPaths)
	packageConfigChanges := filterPackageConfigFiles(changedFiles)
	pnpmWorkspaceChanged := containsPath(changedFiles, "pnpm-workspace.yaml")
	lockfileChanged := containsPath(changedFiles, "pnpm-lock.yaml")

	findings := filterScanFindings(scanReport.Findings, workflowFiles, packageConfigChanges, pnpmWorkspaceChanged, lockfileChanged)
	packageReviews := []PackageReview{}

	if lockfileChanged {
		baseLock, err := loadLockfileAtRef(ctx, root, base)
		if err != nil {
			return nil, err
		}
		headLock, err := loadLockfileAtRef(ctx, root, head)
		if err != nil {
			return nil, err
		}
		changes := diffLockfiles(baseLock, headLock)
		for _, change := range changes {
			review, reviewFindings, err := reviewPackageChange(ctx, root, cfg, opts, change)
			if err != nil {
				return nil, err
			}
			packageReviews = append(packageReviews, review)
			findings = append(findings, reviewFindings...)
		}
	}

	findings = policy.FilterExceptions(cfg, findings, now)
	policy.ApplyFailOn(findings, model.ParseSeverity(cfg.Enforcement.FailOn))

	if !opts.IgnoreBaseline {
		if baselineFile, err := baseline.Load(baseline.Path(headRoot, cfg)); err == nil {
			findings = baseline.FilterFindings(findings, baselineFile)
		}
	}

	for i := range findings {
		rules.ApplyDefaults(&findings[i])
	}
	sortFindings(findings)

	workflowFindings := subsetWorkflowFindings(findings, workflowFiles)
	changedPackages := collectChangedPackageNames(packageReviews)

	result := &Result{
		SchemaVersion:    "1",
		Tool:             "guard",
		Version:          engine.Version,
		Base:             base,
		Head:             head,
		Decision:         "pass",
		ChangedPackages:  changedPackages,
		PackageReviews:   packageReviews,
		WorkflowFindings: workflowFindings,
		Findings:         findings,
	}
	if hasBlockingFindings(findings) {
		result.Decision = "fail"
	}
	result.Summary = summarize(result, changedFiles, lockfileChanged, len(workflowFiles) > 0)
	return result, nil
}

func reviewPackageChange(ctx context.Context, root string, cfg *config.Config, opts Options, change packageChange) (PackageReview, []model.Finding, error) {
	loadPackage := opts.LoadPackage
	if loadPackage == nil {
		loadPackage = diff.FetchPackageContents
	}

	fromContents := emptyContents()
	var err error
	if change.From != "" {
		fromContents, err = loadPackage(ctx, root, change.Package, change.From)
		if err != nil {
			return PackageReview{}, nil, err
		}
	}

	toContents, err := loadPackage(ctx, root, change.Package, change.To)
	if err != nil {
		return PackageReview{}, nil, err
	}

	diffResult := diff.Compare(
		diff.Target{Package: change.Package, From: change.From, To: change.To},
		fromContents,
		toContents,
		cfg.Diff.SuspiciousAPIs,
	)

	registry := opts.Registry
	if registry == nil {
		registry = npm.NewClient(root)
	}

	var beforeMeta *npm.VersionMetadata
	if change.From != "" {
		beforeMeta, _ = registry.Version(ctx, change.Package, change.From)
	}
	afterMeta, _ := registry.Version(ctx, change.Package, change.To)

	beforeTrust := buildTrustProfile(beforeMeta, fromContents)
	afterTrust := buildTrustProfile(afterMeta, toContents)

	var afterAdvisories []osv.Advisory
	if cfg.OSV.Enabled && !opts.DisableOSV {
		client := opts.OSVClient
		if client == nil {
			client = osv.NewClient(root, opts.Offline)
		}
		if client != nil {
			beforeAdvisories, _ := queryAdvisories(ctx, client, change.Package, change.From)
			afterAdvisories, _ = queryAdvisories(ctx, client, change.Package, change.To)
			afterAdvisories = diffAdvisories(beforeAdvisories, afterAdvisories)
		}
	}

	trustBefore := trustScore(beforeTrust)
	trustAfter := trustScore(afterTrust)
	review := PackageReview{
		Package:          change.Package,
		From:             change.From,
		To:               change.To,
		Importers:        append([]string(nil), change.Importers...),
		SemverChange:     semverChange(change.From, change.To),
		RiskScore:        packageRiskScore(diffResult.Signals, afterAdvisories),
		TrustScoreBefore: trustBefore,
		TrustScoreAfter:  trustAfter,
		TrustRegression:  trustAfter < trustBefore,
		Signals:          diffResult.Signals,
		Advisories:       afterAdvisories,
	}

	findings := buildReviewFindings(change, review, beforeTrust, afterTrust)
	return review, findings, nil
}

func buildReviewFindings(change packageChange, review PackageReview, before, after TrustProfile) []model.Finding {
	var findings []model.Finding
	baseEvidence := map[string]any{
		"package":   change.Package,
		"from":      change.From,
		"to":        change.To,
		"importers": append([]string(nil), change.Importers...),
	}

	addFinding := func(f model.Finding) {
		if f.Evidence == nil {
			f.Evidence = map[string]any{}
		}
		for k, v := range baseEvidence {
			if _, ok := f.Evidence[k]; !ok {
				f.Evidence[k] = v
			}
		}
		f.Package = change.Package
		rules.ApplyDefaults(&f)
		findings = append(findings, f)
	}

	hasUnexpectedPatchSignal := false
	for _, signal := range review.Signals {
		switch signal.ID {
		case "diff.install_script.added":
			addFinding(model.Finding{
				RuleID:      "review.diff.install_script.added",
				Category:    model.CategoryDiff,
				Title:       "Upgrade adds an install script",
				Message:     fmt.Sprintf("%s %s -> %s adds a new install lifecycle script.", change.Package, blankVersion(change.From), change.To),
				Remediation: "Block the upgrade unless the install script is expected and reviewed.",
				Evidence:    mergeEvidence(baseEvidence, signal.Evidence),
			})
			hasUnexpectedPatchSignal = true
		case "diff.binary.added":
			addFinding(model.Finding{
				RuleID:      "review.diff.bin.added",
				Category:    model.CategoryDiff,
				Title:       "Upgrade adds a new binary",
				Message:     fmt.Sprintf("%s %s -> %s adds a binary artifact.", change.Package, blankVersion(change.From), change.To),
				Remediation: "Review the new binary artifact before merging.",
				File:        signal.File,
				Evidence:    mergeEvidence(baseEvidence, signal.Evidence),
			})
		case "diff.remote_url.added":
			addFinding(model.Finding{
				RuleID:      "review.diff.remote_url.added",
				Category:    model.CategoryDiff,
				Title:       "Upgrade adds remote fetch or command execution patterns",
				Message:     fmt.Sprintf("%s %s -> %s introduces new remote-fetch or execution behavior.", change.Package, blankVersion(change.From), change.To),
				Remediation: "Review the code change and verify the new behavior is intended.",
				File:        signal.File,
				Evidence:    mergeEvidence(baseEvidence, signal.Evidence),
			})
			hasUnexpectedPatchSignal = true
		}
		if signal.Severity == model.SeverityCritical || signal.Severity == model.SeverityHigh {
			hasUnexpectedPatchSignal = true
		}
	}

	if before.Publisher != "" && after.Publisher != "" && before.Publisher != after.Publisher {
		addFinding(model.Finding{
			RuleID:      "review.trust.publisher.changed",
			Category:    model.CategoryDiff,
			Title:       "Upgrade changes package publisher",
			Message:     fmt.Sprintf("%s publisher changed from %s to %s.", change.Package, before.Publisher, after.Publisher),
			Remediation: "Verify that the publisher change is expected before merging.",
			Evidence: map[string]any{
				"package":            change.Package,
				"previous_publisher": before.Publisher,
				"current_publisher":  after.Publisher,
				"from":               change.From,
				"to":                 change.To,
			},
		})
	}

	if before.Provenance && !after.Provenance {
		addFinding(model.Finding{
			RuleID:      "review.trust.provenance.lost",
			Category:    model.CategoryDiff,
			Title:       "Upgrade loses provenance metadata",
			Message:     fmt.Sprintf("%s had provenance/trust metadata in %s but not in %s.", change.Package, blankVersion(change.From), change.To),
			Remediation: "Verify the release pipeline before merging.",
			Evidence: map[string]any{
				"package": change.Package,
				"from":    change.From,
				"to":      change.To,
			},
		})
	}

	if review.SemverChange == "patch" && hasUnexpectedPatchSignal {
		addFinding(model.Finding{
			RuleID:      "review.trust.semver.unexpected_change",
			Category:    model.CategoryDiff,
			Title:       "Patch release introduces unexpected risky changes",
			Message:     fmt.Sprintf("%s is a patch upgrade but introduces high-risk behavior.", change.Package),
			Remediation: "Treat the upgrade as suspicious and require manual review.",
			Evidence: map[string]any{
				"package":       change.Package,
				"from":          change.From,
				"to":            change.To,
				"semver_change": review.SemverChange,
			},
		})
	}

	for _, advisory := range review.Advisories {
		addFinding(model.Finding{
			RuleID:      "review.osv.new_advisory",
			Category:    model.CategoryOSV,
			Title:       "Upgrade introduces a new advisory",
			Message:     fmt.Sprintf("%s@%s is affected by %s: %s", change.Package, change.To, advisory.ID, advisory.Summary),
			Remediation: "Select a safer version or document an explicit exception.",
			Evidence: map[string]any{
				"package":     change.Package,
				"from":        change.From,
				"to":          change.To,
				"advisory_id": advisory.ID,
			},
		})
	}

	return findings
}

func buildTrustProfile(meta *npm.VersionMetadata, contents *diff.PackageContents) TrustProfile {
	profile := TrustProfile{}
	if meta != nil {
		profile.RegistryHost = meta.RegistryHost
		profile.Publisher = meta.Publisher
		profile.Provenance = meta.Provenance
		profile.TrustedPublishing = meta.TrustedPublishing
		profile.HasSignatures = meta.HasSignatures
	}
	profile.HasInstallScripts = hasInstallScripts(contents)
	profile.HasBin = hasBin(contents)
	return profile
}

func hasInstallScripts(contents *diff.PackageContents) bool {
	if contents == nil || contents.PackageJSON == nil {
		return false
	}
	raw, ok := contents.PackageJSON["scripts"].(map[string]any)
	if !ok {
		return false
	}
	for _, key := range []string{"preinstall", "install", "postinstall", "prepare"} {
		if _, ok := raw[key]; ok {
			return true
		}
	}
	return false
}

func hasBin(contents *diff.PackageContents) bool {
	if contents == nil || contents.PackageJSON == nil {
		return false
	}
	_, ok := contents.PackageJSON["bin"]
	return ok
}

func trustScore(profile TrustProfile) int {
	score := 25
	if profile.Publisher != "" {
		score += 10
	}
	if profile.RegistryHost != "" {
		score += 10
	}
	if profile.Provenance {
		score += 20
	}
	if profile.TrustedPublishing {
		score += 15
	}
	if profile.HasSignatures {
		score += 10
	}
	if !profile.HasInstallScripts {
		score += 5
	}
	if !profile.HasBin {
		score += 5
	}
	if score > 100 {
		return 100
	}
	return score
}

func queryAdvisories(ctx context.Context, client osv.Client, pkg, version string) ([]osv.Advisory, error) {
	if client == nil || version == "" {
		return nil, nil
	}
	return client.Query(ctx, osv.Query{Name: pkg, Version: version, Ecosystem: "npm"})
}

func diffAdvisories(before, after []osv.Advisory) []osv.Advisory {
	seen := map[string]bool{}
	for _, advisory := range before {
		seen[advisory.ID] = true
	}
	var out []osv.Advisory
	for _, advisory := range after {
		if seen[advisory.ID] {
			continue
		}
		out = append(out, advisory)
	}
	return out
}

func loadLockfileAtRef(ctx context.Context, root, ref string) (*lockfile.PNPM, error) {
	b, err := gitutil.ShowFile(ctx, root, ref, "pnpm-lock.yaml")
	if err != nil {
		return nil, err
	}
	return lockfile.Parse(b)
}

func diffLockfiles(before, after *lockfile.PNPM) []packageChange {
	type key struct {
		pkg  string
		from string
		to   string
	}
	grouped := map[key][]string{}
	headRefs := collectImporterRefs(after)
	baseRefs := collectImporterRefs(before)

	allImporters := map[string]bool{}
	for importer := range headRefs {
		allImporters[importer] = true
	}
	for importer := range baseRefs {
		allImporters[importer] = true
	}

	for importer := range allImporters {
		basePkgs := baseRefs[importer]
		headPkgs := headRefs[importer]
		pkgs := map[string]bool{}
		for pkg := range basePkgs {
			pkgs[pkg] = true
		}
		for pkg := range headPkgs {
			pkgs[pkg] = true
		}
		for pkg := range pkgs {
			from := basePkgs[pkg]
			to := headPkgs[pkg]
			if to == "" || from == to {
				continue
			}
			k := key{pkg: pkg, from: from, to: to}
			grouped[k] = append(grouped[k], importer)
		}
	}

	var changes []packageChange
	for k, importers := range grouped {
		sort.Strings(importers)
		changes = append(changes, packageChange{
			Package:   k.pkg,
			From:      k.from,
			To:        k.to,
			Importers: importers,
		})
	}
	sort.Slice(changes, func(i, j int) bool {
		if changes[i].Package == changes[j].Package {
			if changes[i].From == changes[j].From {
				return changes[i].To < changes[j].To
			}
			return changes[i].From < changes[j].From
		}
		return changes[i].Package < changes[j].Package
	})
	return changes
}

func collectImporterRefs(lock *lockfile.PNPM) map[string]map[string]string {
	result := map[string]map[string]string{}
	if lock == nil {
		return result
	}
	for importer, data := range lock.Importers {
		result[importer] = map[string]string{}
		for _, deps := range []map[string]any{data.Dependencies, data.DevDependencies, data.OptionalDependencies} {
			for pkg, version := range collectDeps(deps) {
				result[importer][pkg] = version
			}
		}
	}
	return result
}

func collectDeps(deps map[string]any) map[string]string {
	out := map[string]string{}
	for name, raw := range deps {
		switch value := raw.(type) {
		case string:
			out[name] = strings.TrimPrefix(value, "link:")
		case map[string]any:
			if version, ok := value["version"].(string); ok {
				out[name] = strings.TrimPrefix(version, "link:")
			}
		case map[any]any:
			if version, ok := value["version"].(string); ok {
				out[name] = strings.TrimPrefix(version, "link:")
			}
		}
	}
	return out
}

func filterScanFindings(findings []model.Finding, workflowFiles, packageFiles []string, pnpmWorkspaceChanged, lockfileChanged bool) []model.Finding {
	workflowSet := sliceSet(workflowFiles)
	packageSet := sliceSet(packageFiles)
	var filtered []model.Finding
	for _, finding := range findings {
		if workflowSet[finding.File] {
			filtered = append(filtered, finding)
			continue
		}
		if packageSet[finding.File] {
			filtered = append(filtered, finding)
			continue
		}
		if lockfileChanged && finding.File == "pnpm-lock.yaml" {
			filtered = append(filtered, finding)
			continue
		}
		if pnpmWorkspaceChanged && strings.HasPrefix(finding.RuleID, "pnpm.") {
			filtered = append(filtered, finding)
			continue
		}
	}
	return filtered
}

func filterWorkflowFiles(files, workflowPaths []string) []string {
	var out []string
	for _, path := range files {
		if matchesWorkflowPath(path, workflowPaths) {
			out = append(out, path)
		}
	}
	sort.Strings(out)
	return out
}

func matchesWorkflowPath(path string, workflowPaths []string) bool {
	path = filepath.ToSlash(path)
	for _, workflowPath := range workflowPaths {
		workflowPath = strings.TrimSuffix(filepath.ToSlash(workflowPath), "/")
		if path == workflowPath || strings.HasPrefix(path, workflowPath+"/") {
			return true
		}
	}
	return false
}

func filterPackageConfigFiles(files []string) []string {
	var out []string
	for _, path := range files {
		path = filepath.ToSlash(path)
		if path == "pnpm-workspace.yaml" || strings.HasSuffix(path, "/package.json") || path == "package.json" {
			out = append(out, path)
		}
	}
	sort.Strings(out)
	return out
}

func subsetWorkflowFindings(findings []model.Finding, workflowFiles []string) []model.Finding {
	workflowSet := sliceSet(workflowFiles)
	var out []model.Finding
	for _, finding := range findings {
		if workflowSet[finding.File] {
			out = append(out, finding)
		}
	}
	return out
}

func collectChangedPackageNames(reviews []PackageReview) []string {
	seen := map[string]bool{}
	var out []string
	for _, review := range reviews {
		if seen[review.Package] {
			continue
		}
		seen[review.Package] = true
		out = append(out, review.Package)
	}
	sort.Strings(out)
	return out
}

func summarize(result *Result, changedFiles []string, lockfileChanged, workflowChanged bool) string {
	if len(changedFiles) == 0 {
		return "No changes detected between base and head."
	}
	if len(result.Findings) == 0 && len(result.PackageReviews) == 0 && !workflowChanged && !lockfileChanged {
		return "No dependency, workflow, or pnpm security changes detected."
	}
	if len(result.Findings) == 0 {
		if len(result.PackageReviews) == 0 {
			return "No blocking review findings detected."
		}
		return fmt.Sprintf("Reviewed %d package change(s) with no blocking findings.", len(result.PackageReviews))
	}
	return fmt.Sprintf("%d finding(s) across %d package change(s).", len(result.Findings), len(result.PackageReviews))
}

func hasBlockingFindings(findings []model.Finding) bool {
	for _, finding := range findings {
		if finding.Blocking && !finding.Muted {
			return true
		}
	}
	return false
}

func sortFindings(findings []model.Finding) {
	sort.Slice(findings, func(i, j int) bool {
		if model.SeverityRank(findings[i].Severity) == model.SeverityRank(findings[j].Severity) {
			return findings[i].Fingerprint < findings[j].Fingerprint
		}
		return model.SeverityRank(findings[i].Severity) > model.SeverityRank(findings[j].Severity)
	})
}

func sliceSet(values []string) map[string]bool {
	out := map[string]bool{}
	for _, value := range values {
		out[value] = true
	}
	return out
}

func containsPath(values []string, target string) bool {
	for _, value := range values {
		if filepath.ToSlash(value) == target {
			return true
		}
	}
	return false
}

func semverChange(from, to string) string {
	if from == "" {
		return "added"
	}
	fromMajor, fromMinor, fromPatch, okFrom := parseSemver(from)
	toMajor, toMinor, toPatch, okTo := parseSemver(to)
	if !okFrom || !okTo {
		return "unknown"
	}
	switch {
	case toMajor != fromMajor:
		return "major"
	case toMinor != fromMinor:
		return "minor"
	case toPatch != fromPatch:
		return "patch"
	default:
		return "same"
	}
}

func parseSemver(v string) (int, int, int, bool) {
	v = strings.TrimPrefix(v, "v")
	main := v
	if idx := strings.IndexAny(main, "+-"); idx >= 0 {
		main = main[:idx]
	}
	parts := strings.Split(main, ".")
	if len(parts) < 3 {
		return 0, 0, 0, false
	}
	var nums [3]int
	for i := 0; i < 3; i++ {
		n := 0
		for _, ch := range parts[i] {
			if ch < '0' || ch > '9' {
				return 0, 0, 0, false
			}
			n = n*10 + int(ch-'0')
		}
		nums[i] = n
	}
	return nums[0], nums[1], nums[2], true
}

func packageRiskScore(signals []diff.Signal, advisories []osv.Advisory) int {
	score := 0
	for _, signal := range signals {
		switch signal.Severity {
		case model.SeverityCritical:
			score += 40
		case model.SeverityHigh:
			score += 20
		case model.SeverityMedium:
			score += 8
		default:
			score += 3
		}
	}
	for _, advisory := range advisories {
		switch strings.ToLower(advisory.Severity) {
		case "critical":
			score += 40
		case "high":
			score += 20
		case "medium", "moderate":
			score += 8
		default:
			score += 3
		}
	}
	if score > 100 {
		return 100
	}
	return score
}

func emptyContents() *diff.PackageContents {
	return &diff.PackageContents{
		Files:    map[string][]byte{},
		FileList: []string{},
	}
}

func mergeEvidence(base, extra map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

func blankVersion(v string) string {
	if v == "" {
		return "(new dependency)"
	}
	return v
}
