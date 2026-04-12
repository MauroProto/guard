package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"guard/internal/config"
	"guard/internal/engine"
	"guard/internal/model"
	"guard/internal/ui"
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

	// Step 1: Scan to find issues
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

	// Collect fixable commands (deduplicated, ordered by severity)
	sorted := make([]model.Finding, len(rep.Findings))
	copy(sorted, rep.Findings)
	sort.Slice(sorted, func(i, j int) bool {
		return model.SeverityRank(sorted[i].Severity) > model.SeverityRank(sorted[j].Severity)
	})

	type fixAction struct {
		command  string
		title    string
		blocking bool
		isGuard  bool // can be executed directly
		isShell  bool // shell command
	}

	seen := map[string]bool{}
	var fixes []fixAction
	var manual []fixAction

	for _, f := range sorted {
		if f.Command == "" || f.Muted || seen[f.Command] {
			continue
		}
		seen[f.Command] = true

		act := fixAction{
			command:  f.Command,
			title:    f.Title,
			blocking: f.Blocking,
		}

		// Classify: can we auto-execute this?
		if strings.HasPrefix(f.Command, "guard ") ||
			strings.HasPrefix(f.Command, "pnpm ") ||
			strings.HasPrefix(f.Command, "npm ") ||
			strings.HasPrefix(f.Command, "echo ") {
			act.isShell = true
			fixes = append(fixes, act)
		} else if strings.HasPrefix(f.Command, "gh ") {
			act.isShell = true
			fixes = append(fixes, act)
		} else if strings.HasPrefix(f.Command, "#") {
			// Comment/manual instruction
			manual = append(manual, act)
		} else {
			act.isShell = true
			fixes = append(fixes, act)
		}
	}

	if len(fixes) == 0 && len(manual) == 0 {
		ui.Info(ui.T("fix.no_auto"))
		ui.Newline()
		return nil
	}

	// Show plan
	ui.Newline()
	ui.SectionTitle(fmt.Sprintf("  %s %s (%d)", ui.IconRocket, ui.T("fix.plan"), len(fixes)))

	for i, fix := range fixes {
		marker := ui.Yellow
		label := ui.T("scan.step_optional")
		if fix.blocking {
			marker = ui.Red
			label = ui.T("scan.step_required")
		}
		fmt.Fprintf(os.Stderr, "  %s%s%d.%s %s$ %s%s  %s%s%s\n",
			marker, ui.Bold, i+1, ui.Reset,
			ui.Yellow, fix.command, ui.Reset,
			ui.Dim, label, ui.Reset)
		fmt.Fprintf(os.Stderr, "     %s%s%s\n\n",
			ui.Dim, fix.title, ui.Reset)
	}

	if len(manual) > 0 {
		ui.SectionTitle(fmt.Sprintf("  %s %s", ui.IconInfo, ui.T("fix.manual")))
		for _, m := range manual {
			fmt.Fprintf(os.Stderr, "  %s%s%s\n", ui.Dim, m.command, ui.Reset)
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

	// Confirm
	if !*yes {
		ui.Divider()
		ui.Newline()
		fmt.Fprintf(os.Stderr, "  %s%s%s %s",
			ui.Bold, "?", ui.Reset,
			ui.T("fix.confirm"))
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

	// Execute fixes
	ui.SectionTitle(fmt.Sprintf("  %s %s", ui.IconHammer, ui.T("fix.running")))

	succeeded := 0
	failed := 0

	for _, fix := range fixes {
		sp := ui.NewSpinner(fix.command)

		// Replace "guard " with the current binary path
		cmdStr := fix.command
		self, _ := os.Executable()
		if self != "" {
			cmdStr = strings.Replace(cmdStr, "guard ", self+" ", 1)
		}

		// Execute in shell
		cmd := exec.Command("sh", "-c", cmdStr)
		cmd.Dir = *root
		cmd.Env = os.Environ()
		output, err := cmd.CombinedOutput()

		ui.Pause(200 * time.Millisecond)

		if err != nil {
			sp.StopFail(fix.command)
			if len(output) > 0 {
				// Show first line of error
				lines := strings.SplitN(string(output), "\n", 2)
				fmt.Fprintf(os.Stderr, "     %s%s%s\n\n", ui.Dim, lines[0], ui.Reset)
			}
			failed++
		} else {
			sp.Stop()
			if len(output) > 0 {
				lines := strings.SplitN(strings.TrimSpace(string(output)), "\n", 3)
				for _, line := range lines {
					if line != "" {
						fmt.Fprintf(os.Stderr, "     %s%s%s\n", ui.Dim, line, ui.Reset)
					}
				}
				fmt.Fprintln(os.Stderr)
			}
			succeeded++
		}
	}

	// Summary
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
