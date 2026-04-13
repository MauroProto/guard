package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/MauroProto/guard/internal/config"
	"github.com/MauroProto/guard/internal/engine"
	"github.com/MauroProto/guard/internal/model"
	"github.com/MauroProto/guard/internal/pnpm"
	"github.com/MauroProto/guard/internal/ui"
)

func runFix(args []string) error {
	fs := flag.NewFlagSet("fix", flag.ContinueOnError)
	root := fs.String("root", ".", "repository root")
	dryRun := fs.Bool("dry-run", false, "show what would be fixed without running")
	noColor := fs.Bool("no-color", false, "disable colored output")
	yes := fs.Bool("yes", false, "skip confirmation prompts")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("%w: %v", ErrUsage, err)
	}

	if *noColor {
		ui.SetNoColor(true)
	}

	ui.Header(engine.Version)

	sp := ui.NewSpinner(ui.T("fix.scanning"))
	cfg, err := config.Load(*root, "")
	if err != nil {
		sp.StopFail(fmt.Sprintf("%v", err))
		return err
	}
	rep, err := engine.ScanRepo(context.Background(), *root, cfg, nil)
	ui.Pause(400 * time.Millisecond)
	if err != nil {
		sp.StopFail(fmt.Sprintf("%v", err))
		return err
	}
	sp.Stop()

	if !rep.HasBlockingFindings() && len(rep.Findings) == 0 {
		ui.ResultBox("pass", 0, "")
		ui.Success(ui.T("fix.nothing"))
		ui.Newline()
		return nil
	}

	sorted := make([]model.Finding, len(rep.Findings))
	copy(sorted, rep.Findings)
	sort.Slice(sorted, func(i, j int) bool {
		return model.SeverityRank(sorted[i].Severity) > model.SeverityRank(sorted[j].Severity)
	})

	var pnpmFindings []model.Finding
	var packageJSONFindings []model.Finding
	var fixes []fixAction
	var manual []manualFixAction
	seenExec := map[string]bool{}
	seenManual := map[string]bool{}

	for _, f := range sorted {
		if f.Muted {
			continue
		}
		switch f.RuleID {
		case "pnpm.minimumReleaseAge.missing",
			"pnpm.minimumReleaseAge.too_low",
			"pnpm.blockExoticSubdeps.disabled",
			"pnpm.strictDepBuilds.disabled",
			"pnpm.trustPolicy.disabled":
			pnpmFindings = append(pnpmFindings, f)
			continue
		case "repo.packageManager.unpinned", "repo.nodeEngine.missing":
			packageJSONFindings = append(packageJSONFindings, f)
			continue
		}

		if action := firstAutoFixAction(f); action != nil {
			key := action.CommandString()
			if !seenExec[key] {
				seenExec[key] = true
				fixes = append(fixes, fixAction{
					display:         "$ " + action.CommandString(),
					argv:            append([]string(nil), action.Argv...),
					title:           f.Title,
					blocking:        f.Blocking,
					requiresNetwork: action.RequiresNetwork,
				})
			}
			continue
		}

		step := actionText(f)
		if step == "" {
			step = f.Remediation
		}
		if step != "" && !seenManual[step] {
			seenManual[step] = true
			manual = append(manual, manualFixAction{
				display:  step,
				title:    f.Title,
				blocking: f.Blocking,
			})
		}
	}

	internalPatches := 0
	if len(pnpmFindings) > 0 {
		internalPatches++
	}
	if len(packageJSONFindings) > 0 {
		internalPatches++
	}
	totalFixes := len(fixes) + internalPatches
	if totalFixes == 0 && len(manual) == 0 {
		ui.Info(ui.T("fix.no_auto"))
		ui.Newline()
		return nil
	}

	ui.Newline()
	ui.SectionTitle(fmt.Sprintf("  %s %s (%d)", ui.IconRocket, ui.T("fix.plan"), totalFixes))

	stepNum := 0
	if len(pnpmFindings) > 0 {
		stepNum++
		printPatchPlan(stepNum, "patch pnpm-workspace.yaml", pnpmFindings)
	}
	if len(packageJSONFindings) > 0 {
		stepNum++
		printPackageJSONPlan(stepNum, packageJSONFindings)
	}
	for _, fix := range fixes {
		stepNum++
		marker := ui.Yellow
		label := ui.T("scan.step_optional")
		if fix.blocking {
			marker = ui.Red
			label = ui.T("scan.step_required")
		}
		extra := ""
		if fix.requiresNetwork {
			extra = " + network"
		}
		fmt.Fprintf(os.Stderr, "  %s%s%d.%s %s%s%s  %s%s%s\n",
			marker, ui.Bold, stepNum, ui.Reset,
			ui.Yellow, fix.display, ui.Reset,
			ui.Dim, label+extra, ui.Reset)
		fmt.Fprintf(os.Stderr, "     %s%s%s\n\n", ui.Dim, fix.title, ui.Reset)
	}

	if len(manual) > 0 {
		ui.SectionTitle(fmt.Sprintf("  %s %s", ui.IconInfo, ui.T("fix.manual")))
		for _, m := range manual {
			fmt.Fprintf(os.Stderr, "  %s%s%s\n", ui.Dim, m.display, ui.Reset)
			fmt.Fprintf(os.Stderr, "     %s%s%s\n\n", ui.Dim, m.title, ui.Reset)
		}
	}

	if *dryRun {
		ui.Divider()
		ui.Newline()
		ui.Info(ui.T("init.done_dryrun"))
		ui.Newline()
		return nil
	}

	if !*yes {
		ui.Divider()
		ui.Newline()
		fmt.Fprintf(os.Stderr, "  %s%s%s %s", ui.Bold, "?", ui.Reset, ui.T("fix.confirm"))
		var answer string
		fmt.Scanln(&answer)
		answer = strings.TrimSpace(strings.ToLower(answer))
		if answer != "y" && answer != "yes" && answer != "s" && answer != "si" && answer != "sí" {
			ui.Newline()
			ui.Info(ui.T("fix.cancelled"))
			ui.Newline()
			return nil
		}
		ui.Newline()
	}

	ui.SectionTitle(fmt.Sprintf("  %s %s", ui.IconHammer, ui.T("fix.running")))

	succeeded := 0
	failed := 0

	if len(pnpmFindings) > 0 {
		fixed, patchErr := fixPNPMSettings(*root, pnpmFindings, cfg)
		if patchErr != nil {
			ui.NewSpinner("pnpm-workspace.yaml").StopFail(fmt.Sprintf("patch pnpm settings: %v", patchErr))
			failed++
		} else if len(fixed) > 0 {
			ui.NewSpinner("pnpm-workspace.yaml").Stop()
			for _, desc := range fixed {
				fmt.Fprintf(os.Stderr, "     %s%s%s\n", ui.Dim, desc, ui.Reset)
			}
			fmt.Fprintln(os.Stderr)
			succeeded++
		}
	}

	if len(packageJSONFindings) > 0 {
		fixed, patchErr := fixPackageJSONSettings(*root, packageJSONFindings)
		if patchErr != nil {
			ui.NewSpinner("package.json").StopFail(fmt.Sprintf("patch package settings: %v", patchErr))
			failed++
		} else if len(fixed) > 0 {
			ui.NewSpinner("package.json").Stop()
			for _, desc := range fixed {
				fmt.Fprintf(os.Stderr, "     %s%s%s\n", ui.Dim, desc, ui.Reset)
			}
			fmt.Fprintln(os.Stderr)
			succeeded++
		}
	}

	for _, fix := range fixes {
		sp := ui.NewSpinner(fix.display)
		argv := append([]string(nil), fix.argv...)
		if len(argv) == 0 {
			sp.StopFail(fix.display)
			failed++
			continue
		}
		if argv[0] == "guard" {
			self, _ := os.Executable()
			if self != "" {
				argv[0] = self
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
		cmd.Dir = *root
		cmd.Env = os.Environ()
		output, runErr := cmd.CombinedOutput()
		cancel()

		ui.Pause(200 * time.Millisecond)
		if runErr != nil {
			sp.StopFail(fix.display)
			printCommandOutput(output)
			failed++
			continue
		}
		sp.Stop()
		printCommandOutput(output)
		succeeded++
	}

	ui.Divider()
	ui.Newline()
	if failed == 0 {
		ui.Success(fmt.Sprintf(ui.T("fix.done"), succeeded))
	} else {
		ui.Warn(fmt.Sprintf(ui.T("fix.partial"), succeeded, failed))
	}
	ui.Hint(ui.T("scan.hint_rescan"))
	ui.Newline()

	if failed > 0 {
		return ErrPolicy
	}
	return nil
}

type fixAction struct {
	display         string
	argv            []string
	title           string
	blocking        bool
	requiresNetwork bool
}

type manualFixAction struct {
	display  string
	title    string
	blocking bool
}

func firstAutoFixAction(f model.Finding) *model.Action {
	for i := range f.Actions {
		action := &f.Actions[i]
		if action.Type != model.ActionTypeExec || !action.SafeForAutoFix {
			continue
		}
		if !isAllowedAutoFixAction(action.Argv) {
			continue
		}
		return action
	}
	return nil
}

func isAllowedAutoFixAction(argv []string) bool {
	if len(argv) == 0 {
		return false
	}
	switch argv[0] {
	case "guard", "pnpm", "npm":
		return true
	default:
		return false
	}
}

func printPatchPlan(stepNum int, target string, findings []model.Finding) {
	hasBlocking := false
	for _, f := range findings {
		if f.Blocking {
			hasBlocking = true
			break
		}
	}
	marker := ui.Yellow
	label := ui.T("scan.step_optional")
	if hasBlocking {
		marker = ui.Red
		label = ui.T("scan.step_required")
	}
	fmt.Fprintf(os.Stderr, "  %s%s%d.%s %spatch %s%s  %s%s%s\n",
		marker, ui.Bold, stepNum, ui.Reset,
		ui.Yellow, target, ui.Reset,
		ui.Dim, label, ui.Reset)
	for _, f := range findings {
		fmt.Fprintf(os.Stderr, "     %s%s%s\n", ui.Dim, f.Remediation, ui.Reset)
	}
	fmt.Fprintln(os.Stderr)
}

func printPackageJSONPlan(stepNum int, findings []model.Finding) {
	byFile := map[string][]string{}
	hasBlocking := false
	for _, f := range findings {
		if f.Blocking {
			hasBlocking = true
		}
		byFile[f.File] = append(byFile[f.File], f.RuleID)
	}
	marker := ui.Yellow
	label := ui.T("scan.step_optional")
	if hasBlocking {
		marker = ui.Red
		label = ui.T("scan.step_required")
	}
	fmt.Fprintf(os.Stderr, "  %s%s%d.%s %spatch package.json files%s  %s%s%s\n",
		marker, ui.Bold, stepNum, ui.Reset,
		ui.Yellow, ui.Reset,
		ui.Dim, label, ui.Reset)
	files := make([]string, 0, len(byFile))
	for file := range byFile {
		files = append(files, file)
	}
	sort.Strings(files)
	for _, file := range files {
		fmt.Fprintf(os.Stderr, "     %s%s%s\n", ui.Dim, file, ui.Reset)
	}
	fmt.Fprintln(os.Stderr)
}

func printCommandOutput(output []byte) {
	if len(output) == 0 {
		return
	}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	for i, line := range lines {
		if i >= 3 {
			break
		}
		if line == "" {
			continue
		}
		fmt.Fprintf(os.Stderr, "     %s%s%s\n", ui.Dim, line, ui.Reset)
	}
	fmt.Fprintln(os.Stderr)
}

// fixPNPMSettings loads pnpm-workspace.yaml, patches only the specific fields
// that are broken according to the findings, and saves it back.
func fixPNPMSettings(root string, findings []model.Finding, cfg *config.Config) ([]string, error) {
	ws, err := pnpm.Load(root)
	if err != nil {
		return nil, fmt.Errorf("load pnpm workspace: %w", err)
	}

	var fixed []string
	for _, f := range findings {
		switch f.RuleID {
		case "pnpm.minimumReleaseAge.missing", "pnpm.minimumReleaseAge.too_low":
			ws.MinimumReleaseAge = cfg.PNPM.MinimumReleaseAgeMinutes
			fixed = append(fixed, fmt.Sprintf("minimumReleaseAge → %d", cfg.PNPM.MinimumReleaseAgeMinutes))
		case "pnpm.blockExoticSubdeps.disabled":
			ws.BlockExoticSubdeps = true
			fixed = append(fixed, "blockExoticSubdeps → true")
		case "pnpm.strictDepBuilds.disabled":
			ws.StrictDepBuilds = true
			fixed = append(fixed, "strictDepBuilds → true")
		case "pnpm.trustPolicy.disabled":
			ws.TrustPolicy = "no-downgrade"
			fixed = append(fixed, "trustPolicy → no-downgrade")
		}
	}

	if len(fixed) == 0 {
		return nil, nil
	}
	if err := pnpm.Save(root, ws); err != nil {
		return nil, fmt.Errorf("save pnpm workspace: %w", err)
	}
	return fixed, nil
}

func fixPackageJSONSettings(root string, findings []model.Finding) ([]string, error) {
	needsPackageManager := false
	byFile := map[string]map[string]bool{}
	for _, f := range findings {
		file := f.File
		if file == "" {
			continue
		}
		if byFile[file] == nil {
			byFile[file] = map[string]bool{}
		}
		byFile[file][f.RuleID] = true
		if f.RuleID == "repo.packageManager.unpinned" {
			needsPackageManager = true
		}
	}

	packageManagerValue := ""
	if needsPackageManager {
		version, err := detectPNPMVersion(root)
		if err != nil {
			return nil, err
		}
		packageManagerValue = "pnpm@" + version
	}

	var fixed []string
	files := make([]string, 0, len(byFile))
	for file := range byFile {
		files = append(files, file)
	}
	sort.Strings(files)

	for _, relFile := range files {
		path := filepath.Join(root, filepath.FromSlash(relFile))
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var pkg map[string]any
		if err := json.Unmarshal(b, &pkg); err != nil {
			return nil, err
		}

		changed := false
		if byFile[relFile]["repo.packageManager.unpinned"] {
			pkg["packageManager"] = packageManagerValue
			fixed = append(fixed, relFile+" → packageManager = "+packageManagerValue)
			changed = true
		}
		if byFile[relFile]["repo.nodeEngine.missing"] {
			engines, _ := pkg["engines"].(map[string]any)
			if engines == nil {
				engines = map[string]any{}
			}
			engines["node"] = ">=22"
			pkg["engines"] = engines
			fixed = append(fixed, relFile+` → engines.node = ">=22"`)
			changed = true
		}
		if !changed {
			continue
		}

		out, err := json.MarshalIndent(pkg, "", "  ")
		if err != nil {
			return nil, err
		}
		out = append(out, '\n')
		if err := os.WriteFile(path, out, 0o644); err != nil {
			return nil, err
		}
	}

	return fixed, nil
}

func detectPNPMVersion(root string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "pnpm", "--version")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("detect pnpm version: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}
