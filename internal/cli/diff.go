package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/MauroProto/guard/internal/config"
	diffpkg "github.com/MauroProto/guard/internal/diff"
	"github.com/MauroProto/guard/internal/engine"
	"github.com/MauroProto/guard/internal/model"
	"github.com/MauroProto/guard/internal/ui"
)

func runDiff(args []string) error {
	// Extract positional target before flag parsing.
	var targetStr string
	var flagArgs []string
	for _, a := range args {
		if !strings.HasPrefix(a, "-") && targetStr == "" && strings.Contains(a, "@") {
			targetStr = a
		} else {
			flagArgs = append(flagArgs, a)
		}
	}
	if targetStr == "" {
		return usageError("diff requires: guard d <pkg>@<from>..<to>")
	}

	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	format := fs.String("format", "terminal", "terminal|json|markdown")
	output := fs.String("output", "", "write output to file")
	fromDir := fs.String("from-dir", "", "local directory for the old version")
	toDir := fs.String("to-dir", "", "local directory for the new version")
	root := fs.String("root", ".", "repository root (for policy config)")
	noColor := fs.Bool("no-color", false, "disable colored output")
	if err := fs.Parse(flagArgs); err != nil {
		return fmt.Errorf("%w: %v", ErrUsage, err)
	}

	if *noColor {
		ui.SetNoColor(true)
	}

	target, err := diffpkg.ParseTarget(targetStr)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUsage, err)
	}

	interactive := *format == "terminal" && *output == ""

	if interactive {
		ui.Header(engine.Version)
	}

	cfg, _ := config.Load(*root, "")
	suspiciousAPIs := cfg.Diff.SuspiciousAPIs
	if !cfg.Diff.Enabled {
		result := &diffpkg.DiffResult{
			SchemaVersion: "1",
			Target:        *target,
			Signals:       []diffpkg.Signal{},
			Score:         0,
			Summary:       "Diff analysis disabled by policy.",
			Disabled:      true,
		}
		out, err := renderDiff(result, *format)
		if err != nil {
			return err
		}
		if *output != "" {
			return os.WriteFile(*output, out, 0o644)
		}
		fmt.Print(string(out))
		return nil
	}

	var from, to *diffpkg.PackageContents

	if *fromDir != "" && *toDir != "" {
		if interactive {
			sp := ui.NewSpinner(fmt.Sprintf("Loading %s@%s...", target.Package, target.From))
			from, err = diffpkg.LoadLocalContents(*fromDir)
			ui.Pause(300 * time.Millisecond)
			if err != nil {
				sp.StopFail(fmt.Sprintf("load from-dir: %v", err))
				return fmt.Errorf("load from-dir: %w", err)
			}
			sp.Stop()

			sp = ui.NewSpinner(fmt.Sprintf("Loading %s@%s...", target.Package, target.To))
			to, err = diffpkg.LoadLocalContents(*toDir)
			ui.Pause(300 * time.Millisecond)
			if err != nil {
				sp.StopFail(fmt.Sprintf("load to-dir: %v", err))
				return fmt.Errorf("load to-dir: %w", err)
			}
			sp.Stop()

			sp = ui.NewSpinner("Running heuristics...")
			result := diffpkg.Compare(*target, from, to, suspiciousAPIs)
			ui.Pause(500 * time.Millisecond)
			sp.Stop()

			printDiffInteractive(result)
			return nil
		}

		from, err = diffpkg.LoadLocalContents(*fromDir)
		if err != nil {
			return fmt.Errorf("load from-dir: %w", err)
		}
		to, err = diffpkg.LoadLocalContents(*toDir)
		if err != nil {
			return fmt.Errorf("load to-dir: %w", err)
		}
	} else {
		if interactive {
			sp := ui.NewSpinner(fmt.Sprintf("Fetching %s@%s...", target.Package, target.From))
			from, err = diffpkg.FetchPackageContents(context.Background(), *root, target.Package, target.From)
			ui.Pause(300 * time.Millisecond)
			if err != nil {
				sp.StopFail(fmt.Sprintf("fetch %s@%s: %v", target.Package, target.From, err))
				return err
			}
			sp.Stop()

			sp = ui.NewSpinner(fmt.Sprintf("Fetching %s@%s...", target.Package, target.To))
			to, err = diffpkg.FetchPackageContents(context.Background(), *root, target.Package, target.To)
			ui.Pause(300 * time.Millisecond)
			if err != nil {
				sp.StopFail(fmt.Sprintf("fetch %s@%s: %v", target.Package, target.To, err))
				return err
			}
			sp.Stop()
		} else {
			from, err = diffpkg.FetchPackageContents(context.Background(), *root, target.Package, target.From)
			if err != nil {
				return err
			}
			to, err = diffpkg.FetchPackageContents(context.Background(), *root, target.Package, target.To)
			if err != nil {
				return err
			}
		}
	}

	result := diffpkg.Compare(*target, from, to, suspiciousAPIs)

	out, err := renderDiff(result, *format)
	if err != nil {
		return err
	}
	if *output != "" {
		if err := os.WriteFile(*output, out, 0o644); err != nil {
			return err
		}
		if diffShouldBlock(result, cfg.Diff.FailOnSignals) {
			return ErrPolicy
		}
		return nil
	}
	fmt.Print(string(out))
	if diffShouldBlock(result, cfg.Diff.FailOnSignals) {
		return ErrPolicy
	}
	return nil
}

func printDiffInteractive(r *diffpkg.DiffResult) {
	if len(r.Signals) == 0 {
		ui.ResultBox("pass", 0, "")
		ui.Success(ui.T("diff.clean"))
		ui.Newline()
		return
	}

	decision := "fail"
	if r.Score < 20 {
		decision = "pass"
	}
	summary := fmt.Sprintf("%d signals detected", len(r.Signals))
	ui.ResultBox(decision, r.Score, summary)

	ui.SectionTitle(fmt.Sprintf("  %s Signals (%d)", ui.IconSearch, len(r.Signals)))

	for i, sig := range r.Signals {
		tag := ui.SeverityTag(string(sig.Severity))
		fmt.Fprintf(os.Stderr, "  %s  %s%s%s\n", tag, ui.Bold, sig.Title, ui.Reset)
		fmt.Fprintf(os.Stderr, "       %s%s%s\n", ui.Dim, sig.Message, ui.Reset)
		if sig.File != "" {
			fmt.Fprintf(os.Stderr, "       %s%s:%s %s%s%s\n",
				ui.Dim, ui.T("finding.file"), ui.Reset,
				ui.Cyan, sig.File, ui.Reset)
		}
		fmt.Fprintln(os.Stderr)
		if i < len(r.Signals)-1 {
			ui.Pause(100 * time.Millisecond)
		}
	}

	ui.Divider()
	ui.Newline()
	hasCritical := false
	for _, s := range r.Signals {
		if s.Severity == model.SeverityCritical {
			hasCritical = true
		}
	}
	if hasCritical {
		ui.Fail(ui.T("diff.critical"))
	} else {
		ui.Warn(ui.T("diff.risky"))
	}
	ui.Newline()
}

func renderDiff(result *diffpkg.DiffResult, format string) ([]byte, error) {
	switch format {
	case "json":
		return json.MarshalIndent(result, "", "  ")
	case "markdown":
		return []byte(diffMarkdown(result)), nil
	default:
		return []byte(diffTerminal(result)), nil
	}
}

func diffTerminal(r *diffpkg.DiffResult) string {
	s := fmt.Sprintf("Guard Diff: %s@%s..%s\n", r.Target.Package, r.Target.From, r.Target.To)
	s += fmt.Sprintf("Score: %d/100\n", r.Score)
	s += fmt.Sprintf("Summary: %s\n", r.Summary)
	if len(r.Signals) == 0 {
		s += "\nNo risk signals detected.\n"
		return s
	}
	s += fmt.Sprintf("\nSignals (%d):\n", len(r.Signals))
	for _, sig := range r.Signals {
		s += fmt.Sprintf("  [%s] %s (%s)\n", sig.Severity, sig.Title, sig.ID)
		s += fmt.Sprintf("    %s\n", sig.Message)
		if sig.File != "" {
			s += fmt.Sprintf("    File: %s\n", sig.File)
		}
	}
	return s
}

func diffMarkdown(r *diffpkg.DiffResult) string {
	s := fmt.Sprintf("## Guard Diff: %s@%s..%s\n\n", r.Target.Package, r.Target.From, r.Target.To)
	s += fmt.Sprintf("**Score:** %d/100 | **Summary:** %s\n\n", r.Score, r.Summary)
	if len(r.Signals) == 0 {
		s += "No risk signals detected.\n"
		return s
	}
	s += "| Severity | Signal | Title | File |\n"
	s += "|----------|--------|-------|------|\n"
	for _, sig := range r.Signals {
		file := sig.File
		if file == "" {
			file = "-"
		}
		s += fmt.Sprintf("| %s | `%s` | %s | %s |\n", sig.Severity, sig.ID, sig.Title, file)
	}
	return s
}

func diffShouldBlock(result *diffpkg.DiffResult, failOnSignals []string) bool {
	if result == nil || result.Disabled || len(result.Signals) == 0 {
		return false
	}
	normalized := map[string]bool{}
	for _, signal := range failOnSignals {
		normalized[diffpkg.NormalizeSignalName(signal)] = true
	}
	for _, signal := range result.Signals {
		if normalized[signal.ID] {
			return true
		}
	}
	return false
}
