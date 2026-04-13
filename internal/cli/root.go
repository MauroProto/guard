package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/MauroProto/guard/internal/engine"
	"github.com/MauroProto/guard/internal/locale"
	"github.com/MauroProto/guard/internal/ui"
)

var (
	ErrUsage   = errors.New("usage error")
	ErrPolicy  = errors.New("policy failure")
	ErrRuntime = errors.New("runtime error")
)

// Run dispatches the CLI command.
func Run(args []string) error {
	// Parse global flags first
	var cleaned []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--lang":
			if i+1 < len(args) {
				i++
				switch args[i] {
				case "es", "español", "spanish":
					locale.Set(locale.ES)
				default:
					locale.Set(locale.EN)
				}
			}
		case "--lang=es", "--lang=español":
			locale.Set(locale.ES)
		case "--lang=en", "--lang=english":
			locale.Set(locale.EN)
		case "--no-color":
			ui.SetNoColor(true)
			cleaned = append(cleaned, args[i])
		default:
			cleaned = append(cleaned, args[i])
		}
	}
	args = cleaned

	if len(args) == 0 {
		printHelp()
		return nil
	}

	cmd := args[0]
	rest := args[1:]

	switch cmd {
	case "init", "i":
		return runInit(rest)
	case "scan", "s":
		return runScan(rest)
	case "fix", "f":
		return runFix(rest)
	case "ci", "c":
		return runCI(rest)
	case "diff", "d":
		return runDiff(rest)
	case "approve-build", "approve", "ab":
		return runApproveBuild(rest)
	case "version", "v", "--version", "-v":
		fmt.Printf("guard %s\n", engine.Version)
		return nil
	case "help", "h", "--help", "-h":
		printHelp()
		return nil
	default:
		fmt.Fprintf(os.Stderr, "\n  %s Unknown command: %s\n", ui.IconCross, cmd)
		printHelp()
		return fmt.Errorf("%w: unknown command: %s", ErrUsage, cmd)
	}
}

// ExitCode maps an error to the appropriate process exit code.
func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	if errors.Is(err, ErrUsage) {
		return 2
	}
	return 1
}

func usageError(msg string) error {
	return fmt.Errorf("%w: %s", ErrUsage, msg)
}

func printHelp() {
	t := ui.T
	w := os.Stderr

	fmt.Fprintf(w, "\n  %s  Guard v%s\n", ui.IconShield, engine.Version)
	fmt.Fprintf(w, "  %s\n\n", t("app.tagline"))

	fmt.Fprintf(w, "  %s:\n", t("help.usage"))
	fmt.Fprintf(w, "    guard <command> [flags]\n\n")

	fmt.Fprintf(w, "  %s:\n", t("help.commands"))
	fmt.Fprintf(w, "    scan, s       %s\n", t("cmd.scan"))
	fmt.Fprintf(w, "    fix, f        %s\n", t("cmd.fix"))
	fmt.Fprintf(w, "    init, i       %s\n", t("cmd.init"))
	fmt.Fprintf(w, "    ci, c         %s\n", t("cmd.ci"))
	fmt.Fprintf(w, "    diff, d       %s\n", t("cmd.diff"))
	fmt.Fprintf(w, "    approve, ab   %s\n", t("cmd.approve"))
	fmt.Fprintf(w, "    version, v    %s\n", t("cmd.version"))
	fmt.Fprintf(w, "    help, h       %s\n\n", t("cmd.help"))

	fmt.Fprintf(w, "  %s:\n", t("help.global_flags"))
	fmt.Fprintf(w, "    --lang <en|es>   Language / Idioma\n")
	fmt.Fprintf(w, "    --no-color       Disable colors\n")
	fmt.Fprintf(w, "    --root <path>    Repository root\n")
	fmt.Fprintf(w, "    --format <fmt>   terminal|json|sarif|markdown\n\n")

	fmt.Fprintf(w, "  %s:\n", t("help.examples"))
	fmt.Fprintf(w, "    guard scan            # %s\n", t("cmd.scan"))
	fmt.Fprintf(w, "    guard fix             # %s\n", t("cmd.fix"))
	fmt.Fprintf(w, "    guard init            # %s\n", t("cmd.init"))
	fmt.Fprintf(w, "    guard s --format json # JSON\n")
	fmt.Fprintf(w, "    guard d pkg@1.0..2.0  # %s\n", t("cmd.diff"))
	fmt.Fprintf(w, "    guard ab sharp        # %s\n\n", t("cmd.approve"))

	fmt.Fprintf(w, "  %s\n\n", t("help.hint_lang"))
}
