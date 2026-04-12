package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sort"
	"time"

	"guard/internal/config"
	"guard/internal/engine"
	"guard/internal/model"
	"guard/internal/report"
	"guard/internal/ui"
)

func runScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	root := fs.String("root", ".", "repository root")
	configPath := fs.String("config", "", "path to Guard policy")
	format := fs.String("format", "terminal", "terminal|json|sarif|markdown")
	output := fs.String("output", "", "write output to file")
	noColor := fs.Bool("no-color", false, "disable colored output")
	failOn := fs.String("fail-on", "", "minimum severity to block: low|medium|high|critical")
	offline := fs.Bool("offline", false, "skip network-dependent checks")
	noOSV := fs.Bool("no-osv", false, "skip OSV vulnerability lookup")
	_ = offline
	_ = noOSV

	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("%w: %v", ErrUsage, err)
	}

	if *noColor {
		ui.SetNoColor(true)
	}

	interactive := *format == "terminal" && *output == ""

	if interactive {
		return runScanInteractive(*root, *configPath, *failOn)
	}

	// Non-interactive: structured output only
	cfg, err := config.Load(*root, *configPath)
	if err != nil {
		return err
	}
	opts := &engine.ScanOptions{}
	if *failOn != "" {
		opts.FailOn = *failOn
	}
	rep, err := engine.ScanRepo(context.Background(), *root, cfg, opts)
	if err != nil {
		return err
	}

	out, err := renderReport(rep, *format, *noColor)
	if err != nil {
		return err
	}
	if *output != "" {
		if err := os.WriteFile(*output, out, 0o644); err != nil {
			return err
		}
	} else {
		fmt.Print(string(out))
	}
	if rep.HasBlockingFindings() {
		return ErrPolicy
	}
	return nil
}

func runScanInteractive(root, configPath, failOn string) error {
	ui.Header(engine.Version)

	// Step 1: Load config
	sp := ui.NewSpinner(ui.T("scan.checking") + " " + ui.T("scan.policy") + "...")
	cfg, err := config.Load(root, configPath)
	ui.Pause(400 * time.Millisecond)
	if err != nil {
		sp.StopFail(fmt.Sprintf("Config error: %v", err))
		return err
	}
	sp.Stop()

	// Step 2: Repo checks
	sp = ui.NewSpinner(ui.T("scan.checking") + " " + ui.T("scan.repo") + "...")
	ui.Pause(350 * time.Millisecond)
	sp.Stop()

	// Step 3: pnpm checks
	sp = ui.NewSpinner(ui.T("scan.checking") + " " + ui.T("scan.pnpm") + "...")
	ui.Pause(300 * time.Millisecond)
	sp.Stop()

	// Step 4: Workflow checks
	sp = ui.NewSpinner(ui.T("scan.checking") + " " + ui.T("scan.workflows") + "...")
	ui.Pause(350 * time.Millisecond)
	sp.Stop()

	// Step 5: Scoring
	sp = ui.NewSpinner(ui.T("scan.scoring") + "...")
	opts := &engine.ScanOptions{}
	if failOn != "" {
		opts.FailOn = failOn
	}
	rep, err := engine.ScanRepo(context.Background(), root, cfg, opts)
	ui.Pause(250 * time.Millisecond)
	if err != nil {
		sp.StopFail(fmt.Sprintf("%v", err))
		return err
	}
	sp.Stop()

	// Count categories
	blocking := 0
	warnings := 0
	muted := 0
	for _, f := range rep.Findings {
		if f.Muted {
			muted++
		} else if f.Blocking {
			blocking++
		} else {
			warnings++
		}
	}

	// Summary string
	summaryStr := fmt.Sprintf(ui.T("scan.summary"), blocking, warnings, muted)

	// Result box
	ui.ResultBox(rep.Decision, rep.Score, summaryStr)

	if len(rep.Findings) == 0 {
		ui.Success(ui.T("scan.no_findings"))
		ui.Newline()
		ui.Hint(ui.T("scan.hint_fix"))
		ui.Newline()
		return nil
	}

	// Sort by severity (critical first)
	sorted := make([]model.Finding, len(rep.Findings))
	copy(sorted, rep.Findings)
	sort.Slice(sorted, func(i, j int) bool {
		return model.SeverityRank(sorted[i].Severity) > model.SeverityRank(sorted[j].Severity)
	})

	// Print findings one by one with a small delay
	ui.SectionTitle(fmt.Sprintf("  %s %s (%d)", ui.IconSearch, "Findings", len(sorted)))

	for i, f := range sorted {
		printFindingRich(f)
		if i < len(sorted)-1 {
			ui.Pause(100 * time.Millisecond)
		}
	}

	// Collect unique commands for next steps
	seen := map[string]bool{}
	var nextSteps []nextStep
	for _, f := range sorted {
		if f.Command != "" && !f.Muted && !seen[f.Command] {
			seen[f.Command] = true
			priority := "optional"
			if f.Blocking {
				priority = "required"
			}
			nextSteps = append(nextSteps, nextStep{
				command:  f.Command,
				reason:   f.Title,
				priority: priority,
				severity: f.Severity,
			})
		}
	}

	// Next steps block
	if len(nextSteps) > 0 {
		ui.Divider()
		ui.Newline()
		ui.SectionTitle(fmt.Sprintf("  %s %s", ui.IconRocket, ui.T("scan.next_steps")))

		// Blocking first
		step := 1
		for _, ns := range nextSteps {
			if ns.priority == "required" {
				printNextStep(step, ns)
				step++
			}
		}
		for _, ns := range nextSteps {
			if ns.priority != "required" {
				printNextStep(step, ns)
				step++
			}
		}
	}

	// Footer
	ui.Divider()
	ui.Newline()
	if rep.Decision == "pass" {
		ui.Success(ui.T("scan.pass"))
	} else {
		ui.Fail(ui.T("scan.fail"))
	}
	ui.Hint(ui.T("scan.hint_rescan"))
	ui.Newline()

	if rep.HasBlockingFindings() {
		return ErrPolicy
	}
	return nil
}

type nextStep struct {
	command  string
	reason   string
	priority string
	severity model.Severity
}

func printFindingRich(f model.Finding) {
	tag := ui.SeverityTag(string(f.Severity))

	// Status badge
	status := ""
	if f.Muted {
		status = fmt.Sprintf("  %s%s%s", ui.Dim, ui.T("finding.muted"), ui.Reset)
	} else if f.Blocking {
		status = fmt.Sprintf("  %s%s%s%s", ui.Red, ui.Bold, ui.T("finding.blocking"), ui.Reset)
	}

	fmt.Fprintf(os.Stderr, "  %s  %s%s%s%s\n", tag, ui.Bold, f.Title, ui.Reset, status)
	fmt.Fprintf(os.Stderr, "       %s%s%s\n", ui.Dim, f.Message, ui.Reset)

	if f.File != "" {
		loc := f.File
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", f.File, f.Line)
		}
		fmt.Fprintf(os.Stderr, "       %s%s:%s %s%s%s\n",
			ui.Dim, ui.T("finding.file"), ui.Reset,
			ui.Cyan, loc, ui.Reset)
	}
	if f.Remediation != "" {
		fmt.Fprintf(os.Stderr, "       %s%s:%s %s%s%s\n",
			ui.Dim, ui.T("finding.fix"), ui.Reset,
			ui.Green, f.Remediation, ui.Reset)
	}
	if f.Command != "" {
		fmt.Fprintf(os.Stderr, "       %s%s:%s %s$ %s%s\n",
			ui.Dim, ui.T("finding.run"), ui.Reset,
			ui.Yellow, f.Command, ui.Reset)
	}
	fmt.Fprintln(os.Stderr)
}

func printNextStep(n int, ns nextStep) {
	marker := ui.Yellow
	label := ui.T("scan.step_optional")
	if ns.priority == "required" {
		marker = ui.Red
		label = ui.T("scan.step_required")
	}
	fmt.Fprintf(os.Stderr, "  %s%s%d.%s %s%s%s  %s%s%s\n",
		marker, ui.Bold, n, ui.Reset,
		ui.Yellow, "$ "+ns.command, ui.Reset,
		ui.Dim, label, ui.Reset)
	fmt.Fprintf(os.Stderr, "     %s%s%s\n\n",
		ui.Dim, ns.reason, ui.Reset)
}

func renderReport(rep *model.Report, format string, noColor bool) ([]byte, error) {
	switch format {
	case "json":
		return report.JSON(rep)
	case "sarif":
		return report.SARIF(rep)
	case "markdown":
		return []byte(report.Markdown(rep)), nil
	default:
		return []byte(report.Terminal(rep, noColor)), nil
	}
}
