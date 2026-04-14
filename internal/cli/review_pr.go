package cli

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/MauroProto/guard/internal/review"
	"github.com/MauroProto/guard/internal/ui"
)

func runReviewPR(args []string) error {
	fs := flag.NewFlagSet("review-pr", flag.ContinueOnError)
	root := fs.String("root", ".", "repository root")
	configPath := fs.String("config", "", "path to Guard policy")
	base := fs.String("base", "", "base git ref")
	head := fs.String("head", "HEAD", "head git ref")
	format := fs.String("format", "terminal", "terminal|json|markdown")
	output := fs.String("output", "", "write output to file")
	noColor := fs.Bool("no-color", false, "disable colored output")
	ignoreBaseline := fs.Bool("ignore-baseline", false, "ignore stored baseline entries")
	offline := fs.Bool("offline", false, "skip network-dependent checks")
	noOSV := fs.Bool("no-osv", false, "skip OSV review")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("%w: %v", ErrUsage, err)
	}
	if *noColor {
		ui.SetNoColor(true)
	}

	result, err := review.RunPRReview(context.Background(), *root, review.Options{
		Base:           *base,
		Head:           *head,
		ConfigPath:     *configPath,
		IgnoreBaseline: *ignoreBaseline,
		Offline:        *offline,
		DisableOSV:     *noOSV,
	})
	if err != nil {
		return err
	}

	var out []byte
	switch *format {
	case "json":
		out, err = review.JSON(result)
	case "markdown":
		out = []byte(review.Markdown(result))
	default:
		out = []byte(review.Terminal(result))
	}
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

	if result.Decision == "fail" {
		return ErrPolicy
	}
	return nil
}
