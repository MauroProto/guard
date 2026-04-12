package cli

import (
	"flag"
	"fmt"
	"strings"
	"time"

	"guard/internal/config"
	"guard/internal/engine"
	"guard/internal/pnpm"
	"guard/internal/policy"
	"guard/internal/ui"
)

func runApproveBuild(args []string) error {
	// Extract positional package name.
	var pkg string
	var flagArgs []string
	for _, a := range args {
		if !strings.HasPrefix(a, "-") && pkg == "" {
			pkg = a
		} else {
			flagArgs = append(flagArgs, a)
		}
	}
	if pkg == "" {
		return usageError("approve requires: guard approve <package-name>")
	}

	fs := flag.NewFlagSet("approve-build", flag.ContinueOnError)
	root := fs.String("root", ".", "repository root")
	dryRun := fs.Bool("dry-run", false, "preview changes without writing")
	reason := fs.String("reason", "Approved via guard approve-build", "reason for the approval")
	version := fs.String("version", "", "version constraint (informational)")
	noColor := fs.Bool("no-color", false, "disable colored output")
	if err := fs.Parse(flagArgs); err != nil {
		return fmt.Errorf("%w: %v", ErrUsage, err)
	}
	_ = version

	if *noColor {
		ui.SetNoColor(true)
	}

	ui.Header(engine.Version)

	if *dryRun {
		ui.Info(fmt.Sprintf("Dry run — approving %s", pkg))
		ui.Newline()
		ui.FileWouldCreate(fmt.Sprintf("pnpm-workspace.yaml → allowBuilds[%q] = true", pkg))
		ui.FileWouldCreate(fmt.Sprintf(".guard/policy.yaml → package exception for %q", pkg))
		ui.Divider()
		ui.Newline()
		ui.Info(ui.T("init.done_dryrun"))
		ui.Newline()
		return nil
	}

	// Step 1: Load workspace
	sp := ui.NewSpinner("Loading workspace...")
	ws, err := pnpm.Load(*root)
	ui.Pause(300 * time.Millisecond)
	if err != nil {
		sp.StopFail(fmt.Sprintf("load workspace: %v", err))
		return fmt.Errorf("load workspace: %w", err)
	}
	if ws.AllowBuilds == nil {
		ws.AllowBuilds = map[string]bool{}
	}
	sp.Stop()

	// Step 2: Load policy
	sp = ui.NewSpinner("Loading policy...")
	cfg, err := config.Load(*root, "")
	ui.Pause(200 * time.Millisecond)
	if err != nil {
		sp.StopFail(fmt.Sprintf("%v", err))
		return err
	}
	sp.Stop()

	// Step 3: Update workspace
	sp = ui.NewSpinner(fmt.Sprintf("Updating pnpm-workspace.yaml → allowBuilds[%q]", pkg))
	ws.AllowBuilds[pkg] = true
	if err := pnpm.Save(*root, ws); err != nil {
		sp.StopFail(err.Error())
		return fmt.Errorf("save workspace: %w", err)
	}
	ui.Pause(300 * time.Millisecond)
	sp.Stop()

	// Step 4: Update policy
	expiry := time.Now().AddDate(0, 6, 0)
	sp = ui.NewSpinner(fmt.Sprintf("Updating .guard/policy.yaml → exception expires %s", expiry.Format("2006-01-02")))
	policy.AddPackageException(cfg, pkg, *reason, expiry)
	if err := config.Save(*root, "", cfg); err != nil {
		sp.StopFail(err.Error())
		return fmt.Errorf("save policy: %w", err)
	}
	ui.Pause(300 * time.Millisecond)
	sp.Stop()

	// Result
	ui.Divider()
	ui.Newline()
	ui.Success(fmt.Sprintf(ui.T("approve.done"), pkg))
	ui.Newline()
	return nil
}
