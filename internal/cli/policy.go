package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"strings"

	"github.com/MauroProto/guard/internal/config"
)

func runPolicy(args []string) error {
	if len(args) == 0 {
		return usageError("policy requires a subcommand (lint)")
	}
	switch args[0] {
	case "lint":
		return runPolicyLint(args[1:])
	default:
		return usageError("unknown policy subcommand: " + args[0])
	}
}

func runPolicyLint(args []string) error {
	fs := flag.NewFlagSet("policy lint", flag.ContinueOnError)
	root := fs.String("root", ".", "repository root")
	configPath := fs.String("config", "", "path to Guard policy")
	format := fs.String("format", "terminal", "terminal|json")
	noColor := fs.Bool("no-color", false, "disable colored output")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("%w: %v", ErrUsage, err)
	}
	_ = noColor

	cfg, err := config.Load(*root, *configPath)
	if err != nil {
		return err
	}
	issues := config.Lint(*root, cfg)

	switch *format {
	case "json":
		out, err := json.MarshalIndent(map[string]any{
			"schemaVersion": "1",
			"tool":          "guard",
			"issues":        issues,
		}, "", "  ")
		if err != nil {
			return err
		}
		fmt.Print(string(out))
	default:
		if len(issues) == 0 {
			fmt.Println("Policy lint passed.")
		} else {
			fmt.Println("Policy lint found issues:")
			for _, issue := range issues {
				line := fmt.Sprintf("  [%s] %s", strings.ToUpper(issue.Severity), issue.Message)
				if issue.Path != "" {
					line += " (" + issue.Path + ")"
				}
				fmt.Println(line)
			}
		}
	}

	if hasLintErrors(issues) {
		return ErrPolicy
	}
	return nil
}

func hasLintErrors(issues []config.LintIssue) bool {
	for _, issue := range issues {
		if issue.Severity == "error" {
			return true
		}
	}
	return false
}
