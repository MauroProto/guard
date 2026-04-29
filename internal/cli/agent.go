package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/MauroProto/guard/internal/agentaudit"
	"github.com/MauroProto/guard/internal/report"
)

func runAgent(args []string) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		printAgentHelp()
		return nil
	}
	switch args[0] {
	case "audit":
		return runAgentAudit(args[1:])
	default:
		return usageError("unknown agent command: " + args[0])
	}
}

func runAgentAudit(args []string) error {
	fs := flag.NewFlagSet("agent audit", flag.ContinueOnError)
	root := fs.String("root", ".", "repository root")
	home := fs.String("home", "", "home directory to inspect")
	format := fs.String("format", "terminal", "terminal|json")
	failOn := fs.String("fail-on", "high", "minimum severity to block, or none")
	noColor := fs.Bool("no-color", false, "disable colored output")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("%w: %v", ErrUsage, err)
	}

	rep, err := agentaudit.Audit(context.Background(), agentaudit.Options{
		Root:   *root,
		Home:   *home,
		FailOn: *failOn,
	})
	if err != nil {
		return err
	}

	switch strings.ToLower(*format) {
	case "json":
		out, err := report.JSON(rep)
		if err != nil {
			return err
		}
		fmt.Println(string(out))
	case "terminal", "":
		fmt.Print(report.Terminal(rep, *noColor))
	default:
		return usageError("unsupported format: " + *format)
	}

	if rep.HasBlockingFindings() {
		return ErrPolicy
	}
	return nil
}

func printAgentHelp() {
	w := os.Stderr
	fmt.Fprintln(w, "guard agent audit [flags]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Audit installed agent tooling such as MCP servers, skills, plugins, and hooks.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Flags:")
	fmt.Fprintln(w, "  --root <path>       Repository root")
	fmt.Fprintln(w, "  --home <path>       Home directory to inspect")
	fmt.Fprintln(w, "  --format <fmt>      terminal|json")
	fmt.Fprintln(w, "  --fail-on <level>   critical|high|medium|low|none")
	fmt.Fprintln(w, "  --no-color          Disable colors")
}
