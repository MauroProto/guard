package cli

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"guard/internal/config"
	"guard/internal/engine"
	"guard/internal/pnpm"
	"guard/internal/templates"
	"guard/internal/ui"
)

func runInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	root := fs.String("root", ".", "repository root")
	dryRun := fs.Bool("dry-run", false, "preview changes without writing")
	force := fs.Bool("force", false, "overwrite existing files")
	preset := fs.String("preset", "balanced", "security preset: strict|balanced|local")
	minAge := fs.Int("minimum-release-age", 0, "minimum release age in minutes (overrides preset)")
	orgScope := fs.String("org-scope", "", "org scope to exclude from release age (e.g. @myorg/*)")
	noColor := fs.Bool("no-color", false, "disable colored output")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("%w: %v", ErrUsage, err)
	}

	if *noColor {
		ui.SetNoColor(true)
	}

	ui.Header(engine.Version)

	// Step 1: Load preset
	sp := ui.NewSpinner(fmt.Sprintf("Loading preset: %s...", *preset))
	cfg, err := config.Preset(*preset)
	ui.Pause(400 * time.Millisecond)
	if err != nil {
		sp.StopFail(fmt.Sprintf("%v", err))
		return fmt.Errorf("%w: %v", ErrUsage, err)
	}
	sp.Stop()

	if *minAge > 0 {
		cfg.PNPM.MinimumReleaseAgeMinutes = *minAge
	}
	if *orgScope != "" {
		cfg.PNPM.MinimumReleaseAgeExclude = append(cfg.PNPM.MinimumReleaseAgeExclude, *orgScope)
	}

	ws := pnpm.DefaultWorkspace()
	ws.MinimumReleaseAge = cfg.PNPM.MinimumReleaseAgeMinutes
	if *orgScope != "" {
		ws.MinimumReleaseAgeExclude = append(ws.MinimumReleaseAgeExclude, *orgScope)
	}

	files := []struct {
		rel  string
		icon string
		data func() ([]byte, error)
	}{
		{".guard/policy.yaml", "🔒", func() ([]byte, error) { return config.MarshalYAML(cfg) }},
		{"pnpm-workspace.yaml", "📦", func() ([]byte, error) { return pnpm.MarshalYAML(ws) }},
		{".github/workflows/guard-ci.yml", "⚙️ ", func() ([]byte, error) { return templates.GuardCI() }},
		{"AGENTS.md", "📄", func() ([]byte, error) { return templates.Agents() }},
		{"CLAUDE.md", "🤖", func() ([]byte, error) { return templates.Claude() }},
	}

	if *dryRun {
		ui.Info("Dry run — no files will be written")
		ui.Newline()
		for _, f := range files {
			path := filepath.Join(*root, f.rel)
			if _, err := os.Stat(path); err == nil {
				ui.FileSkipped(f.icon + " " + f.rel)
			} else {
				ui.FileWouldCreate(f.icon + " " + f.rel)
			}
			ui.Pause(150 * time.Millisecond)
		}
		ui.Divider()
		ui.Newline()
		ui.Info(ui.T("init.done_dryrun"))
		ui.Newline()
		return nil
	}

	// Check existing
	policyPath := filepath.Join(*root, ".guard", "policy.yaml")
	if !*force {
		if _, err := os.Stat(policyPath); err == nil {
			ui.Warn(ui.T("init.already"))
			ui.Newline()
			return fmt.Errorf("%w: %s already exists (use --force)", ErrUsage, policyPath)
		}
	}

	// Step 2: Generate files one by one
	sp = ui.NewSpinner("Generating secure baseline...")
	ui.Pause(300 * time.Millisecond)
	sp.Stop()

	ui.Newline()
	for _, f := range files {
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
		ui.Pause(300 * time.Millisecond)
		sp.Stop()
	}

	// Result
	ui.Divider()
	ui.Newline()
	ui.Success(ui.T("init.done"))
	ui.Hint(ui.T("help.hint_scan"))
	ui.Newline()
	return nil
}
