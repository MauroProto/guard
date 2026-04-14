package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/MauroProto/guard/internal/config"
	"github.com/MauroProto/guard/internal/engine"
	"github.com/MauroProto/guard/internal/report"
	"github.com/MauroProto/guard/internal/ui"
)

func runCI(args []string) error {
	fs := flag.NewFlagSet("ci", flag.ContinueOnError)
	root := fs.String("root", ".", "repository root")
	format := fs.String("format", "terminal", "terminal|json|sarif")
	output := fs.String("output", "", "write output to file")
	failOn := fs.String("fail-on", "", "minimum severity to block")
	ignoreBaseline := fs.Bool("ignore-baseline", false, "ignore stored baseline entries")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("%w: %v", ErrUsage, err)
	}

	ui.SetNoColor(true)
	interactive := *format == "terminal" && *output == ""

	if interactive {
		ui.Header(engine.Version)

		sp := ui.NewSpinner(ui.T("ci.start"))
		cfg, err := config.Load(*root, "")
		ui.Pause(300 * time.Millisecond)
		if err != nil {
			sp.StopFail(fmt.Sprintf("%v", err))
			return err
		}
		sp.Stop()

		sp = ui.NewSpinner(ui.T("scan.checking") + " " + ui.T("scan.repo") + "...")
		ui.Pause(250 * time.Millisecond)
		sp.Stop()

		sp = ui.NewSpinner(ui.T("scan.checking") + " " + ui.T("scan.pnpm") + "...")
		ui.Pause(200 * time.Millisecond)
		sp.Stop()

		sp = ui.NewSpinner(ui.T("scan.checking") + " " + ui.T("scan.workflows") + "...")
		ui.Pause(250 * time.Millisecond)
		sp.Stop()

		sp = ui.NewSpinner(ui.T("scan.scoring") + "...")
		opts := &engine.ScanOptions{}
		if *failOn != "" {
			opts.FailOn = *failOn
		}
		rep, scanErr := engine.ScanRepo(context.Background(), *root, cfg, opts)
		ui.Pause(200 * time.Millisecond)
		if scanErr != nil {
			sp.StopFail(fmt.Sprintf("%v", scanErr))
			return scanErr
		}
		sp.Stop()
		applyBaselineToReport(*root, cfg, rep, *ignoreBaseline)

		blocking := 0
		for _, f := range rep.Findings {
			if f.Blocking && !f.Muted {
				blocking++
			}
		}
		summary := fmt.Sprintf("%d findings, %d blocking", len(rep.Findings), blocking)
		ui.ResultBox(rep.Decision, rep.Score, summary)

		if rep.Decision == "pass" {
			ui.Success(ui.T("ci.pass"))
		} else {
			ui.Fail(ui.T("ci.fail"))
		}
		ui.Newline()

		if rep.HasBlockingFindings() {
			return ErrPolicy
		}
		return nil
	}

	// Non-interactive structured output
	cfg, err := config.Load(*root, "")
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
	applyBaselineToReport(*root, cfg, rep, *ignoreBaseline)

	var out []byte
	switch *format {
	case "json":
		out, err = report.JSON(rep)
	case "sarif":
		out, err = report.SARIF(rep)
	default:
		out = []byte(report.Terminal(rep, true))
	}
	if err != nil {
		return err
	}

	if *output != "" {
		if err := os.WriteFile(*output, out, 0o644); err != nil {
			return err
		}
		if *format != "json" {
			jsonBytes, jerr := report.JSON(rep)
			if jerr == nil {
				jsonPath := strings.TrimSuffix(*output, filepath.Ext(*output)) + ".json"
				_ = os.WriteFile(jsonPath, jsonBytes, 0o644)
			}
		}
	} else {
		fmt.Print(string(out))
	}

	if rep.HasBlockingFindings() {
		return ErrPolicy
	}
	return nil
}
