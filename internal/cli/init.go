package cli

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/MauroProto/guard/internal/config"
	"github.com/MauroProto/guard/internal/engine"
	"github.com/MauroProto/guard/internal/pnpm"
	"github.com/MauroProto/guard/internal/templates"
	"github.com/MauroProto/guard/internal/ui"
)

func runInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	root := fs.String("root", ".", "repository root")
	dryRun := fs.Bool("dry-run", false, "preview changes without writing")
	force := fs.Bool("force", false, "overwrite generated template files")
	preset := fs.String("preset", "balanced", "security preset: strict|balanced|local")
	minAge := fs.Int("minimum-release-age", 0, "minimum release age in minutes (overrides preset)")
	orgScope := fs.String("org-scope", "", "org scope to exclude from release age (e.g. @myorg/*)")
	addCI := fs.Bool("add-ci", false, "create .github/workflows/guard-ci.yml")
	withAIDocs := fs.Bool("with-ai-docs", false, "create AGENTS.md and CLAUDE.md")
	noColor := fs.Bool("no-color", false, "disable colored output")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("%w: %v", ErrUsage, err)
	}

	if *noColor {
		ui.SetNoColor(true)
	}

	ui.Header(engine.Version)

	sp := ui.NewSpinner(fmt.Sprintf("Loading preset: %s...", *preset))
	presetCfg, err := config.Preset(*preset)
	ui.Pause(400 * time.Millisecond)
	if err != nil {
		sp.StopFail(fmt.Sprintf("%v", err))
		return fmt.Errorf("%w: %v", ErrUsage, err)
	}
	sp.Stop()

	if *minAge > 0 {
		presetCfg.PNPM.MinimumReleaseAgeMinutes = *minAge
	}
	if *orgScope != "" {
		presetCfg.PNPM.MinimumReleaseAgeExclude = appendUnique(presetCfg.PNPM.MinimumReleaseAgeExclude, *orgScope)
	}

	cfg, err := config.Load(*root, "")
	if err != nil {
		return err
	}
	applyPresetConfig(cfg, presetCfg)

	ws, err := loadOrDefaultWorkspace(*root)
	if err != nil {
		return err
	}
	applyPresetWorkspace(ws, cfg.PNPM)

	templateFiles := []struct {
		rel  string
		icon string
		data func() ([]byte, error)
	}{}
	if *addCI {
		templateFiles = append(templateFiles, struct {
			rel  string
			icon string
			data func() ([]byte, error)
		}{
			rel:  ".github/workflows/guard-ci.yml",
			icon: "⚙️ ",
			data: templates.GuardCI,
		})
	}
	if *withAIDocs {
		templateFiles = append(templateFiles,
			struct {
				rel  string
				icon string
				data func() ([]byte, error)
			}{rel: "AGENTS.md", icon: "📄", data: templates.Agents},
			struct {
				rel  string
				icon string
				data func() ([]byte, error)
			}{rel: "CLAUDE.md", icon: "🤖", data: templates.Claude},
		)
	}

	if !*force {
		for _, f := range templateFiles {
			path := filepath.Join(*root, f.rel)
			if _, err := os.Stat(path); err == nil {
				ui.Warn(ui.T("init.already"))
				ui.Newline()
				return fmt.Errorf("%w: %s already exists (use --force)", ErrUsage, path)
			}
		}
	}

	if *dryRun {
		ui.Info("Dry run — no files will be written")
		ui.Newline()
		reportInitTarget(*root, ".guard/policy.yaml")
		reportInitTarget(*root, "pnpm-workspace.yaml")
		for _, f := range templateFiles {
			reportInitTarget(*root, f.rel)
			ui.Pause(150 * time.Millisecond)
		}
		ui.Divider()
		ui.Newline()
		ui.Info(ui.T("init.done_dryrun"))
		ui.Newline()
		return nil
	}

	ui.Newline()
	ui.NewSpinner("Updating .guard/policy.yaml").Stop()
	if err := config.Save(*root, "", cfg); err != nil {
		return err
	}

	ui.NewSpinner("Updating pnpm-workspace.yaml").Stop()
	if err := pnpm.Save(*root, ws); err != nil {
		return err
	}

	for _, f := range templateFiles {
		sp = ui.NewSpinner(f.icon + " " + f.rel)
		data, err := f.data()
		if err != nil {
			sp.StopFail(fmt.Sprintf("generate %s: %v", f.rel, err))
			return fmt.Errorf("generate %s: %w", f.rel, err)
		}
		path := filepath.Join(*root, f.rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			sp.StopFail(err.Error())
			return err
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			sp.StopFail(err.Error())
			return err
		}
		ui.Pause(250 * time.Millisecond)
		sp.Stop()
	}

	ui.Divider()
	ui.Newline()
	ui.Success(ui.T("init.done"))
	ui.Hint(ui.T("help.hint_scan"))
	ui.Newline()
	return nil
}

func applyPresetConfig(dst, preset *config.Config) {
	if dst.Project.Name == "" {
		dst.Project.Name = preset.Project.Name
	}
	dst.Version = preset.Version
	dst.Project.Ecosystem = preset.Project.Ecosystem
	dst.Project.PackageManager = preset.Project.PackageManager
	dst.Enforcement = preset.Enforcement
	dst.PNPM = preset.PNPM
	dst.GitHub = preset.GitHub
	dst.OSV = preset.OSV
	dst.Diff = preset.Diff
}

func loadOrDefaultWorkspace(root string) (*pnpm.Workspace, error) {
	ws, err := pnpm.Load(root)
	if err == nil {
		return ws, nil
	}
	if os.IsNotExist(err) {
		return pnpm.DefaultWorkspace(), nil
	}
	return nil, err
}

func applyPresetWorkspace(ws *pnpm.Workspace, cfg config.PNPM) {
	defaults := pnpm.DefaultWorkspace()
	if len(ws.Packages) == 0 {
		ws.Packages = append([]string(nil), defaults.Packages...)
	}
	if ws.MinimumReleaseAge < cfg.MinimumReleaseAgeMinutes {
		ws.MinimumReleaseAge = cfg.MinimumReleaseAgeMinutes
	}
	ws.MinimumReleaseAgeExclude = appendUnique(ws.MinimumReleaseAgeExclude, cfg.MinimumReleaseAgeExclude...)
	if cfg.TrustPolicy == "no-downgrade" {
		ws.TrustPolicy = cfg.TrustPolicy
	}
	if cfg.BlockExoticSubdeps {
		ws.BlockExoticSubdeps = true
	}
	if cfg.StrictDepBuilds {
		ws.StrictDepBuilds = true
	}
	if ws.AllowBuilds == nil {
		ws.AllowBuilds = map[string]bool{}
	}
	ws.PackageManagerStrict = true
	ws.ManagePackageManagerVersions = true
	if ws.TrustPolicyIgnoreAfter == 0 {
		ws.TrustPolicyIgnoreAfter = defaults.TrustPolicyIgnoreAfter
	}
}

func reportInitTarget(root, rel string) {
	path := filepath.Join(root, rel)
	if _, err := os.Stat(path); err == nil {
		ui.FileSkipped(rel + " (patched)")
	} else {
		ui.FileWouldCreate(rel)
	}
}

func appendUnique(values []string, extras ...string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(values)+len(extras))
	for _, value := range append(values, extras...) {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	return result
}
