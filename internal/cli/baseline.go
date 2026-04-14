package cli

import (
	"context"
	"flag"
	"fmt"
	"time"

	"github.com/MauroProto/guard/internal/baseline"
	"github.com/MauroProto/guard/internal/config"
	"github.com/MauroProto/guard/internal/engine"
)

var baselineScanRepo = engine.ScanRepo

func runBaseline(args []string) error {
	if len(args) == 0 {
		return usageError("baseline requires a subcommand (record)")
	}
	switch args[0] {
	case "record":
		return runBaselineRecord(args[1:])
	default:
		return usageError("unknown baseline subcommand: " + args[0])
	}
}

func runBaselineRecord(args []string) error {
	fs := flag.NewFlagSet("baseline record", flag.ContinueOnError)
	root := fs.String("root", ".", "repository root")
	configPath := fs.String("config", "", "path to Guard policy")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("%w: %v", ErrUsage, err)
	}

	cfg, err := config.Load(*root, *configPath)
	if err != nil {
		return err
	}
	rep, err := baselineScanRepo(context.Background(), *root, cfg, &engine.ScanOptions{
		Now: time.Now().UTC(),
	})
	if err != nil {
		return err
	}
	path := baseline.Path(*root, cfg)
	if err := baseline.Save(path, rep.Findings, time.Now().UTC()); err != nil {
		return err
	}
	fmt.Printf("Baseline recorded at %s\n", path)
	return nil
}
