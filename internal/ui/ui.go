package ui

import (
	"fmt"
	"os"
	"strings"

	"guard/internal/locale"
)

// ANSI color/style codes — exported so CLI files can reference them directly.
const (
	Reset   = "\033[0m"
	Bold    = "\033[1m"
	Dim     = "\033[2m"
	Italic  = "\033[3m"
	Red     = "\033[31m"
	Green   = "\033[32m"
	Yellow  = "\033[33m"
	Blue    = "\033[34m"
	Magenta = "\033[35m"
	Cyan    = "\033[36m"
	White   = "\033[37m"
	BgRed   = "\033[41m"
	BgGreen = "\033[42m"
	BgBlue  = "\033[44m"
	BgWhite = "\033[47m"
)

// Icons
const (
	IconCheck   = "✔"
	IconCross   = "✖"
	IconWarn    = "⚠"
	IconInfo    = "ℹ"
	IconArrow   = "→"
	IconDot     = "●"
	IconStar    = "★"
	IconShield  = "🛡"
	IconPackage = "📦"
	IconFile    = "📄"
	IconSearch  = "🔍"
	IconRocket  = "🚀"
	IconHammer  = "🔨"
)

var noColorFlag bool

// SetNoColor disables ANSI color output.
func SetNoColor(v bool) { noColorFlag = v }

// c returns the ANSI code, or empty string if no-color is set.
func c(code string) string {
	if noColorFlag {
		return ""
	}
	return code
}

// T is a shorthand for locale.T.
func T(key string) string { return locale.T(key) }

// ──────────────────────────────────────────────
// Header / Footer
// ──────────────────────────────────────────────

// Header prints the Guard banner.
func Header(version string) {
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "  %s%s  Guard%s %sv%s%s\n",
		c(Bold+Cyan), IconShield, c(Reset),
		c(Dim), version, c(Reset))
	fmt.Fprintf(os.Stderr, "  %s%s%s\n",
		c(Dim), T("app.tagline"), c(Reset))
	fmt.Fprintf(os.Stderr, "  %s%s%s\n\n",
		c(Dim), strings.Repeat("─", 44), c(Reset))
}

// ──────────────────────────────────────────────
// Status messages
// ──────────────────────────────────────────────

// Success prints a green check message.
func Success(msg string) {
	fmt.Fprintf(os.Stderr, "  %s%s%s %s\n", c(Green), IconCheck, c(Reset), msg)
}

// Fail prints a red cross message.
func Fail(msg string) {
	fmt.Fprintf(os.Stderr, "  %s%s%s %s\n", c(Red), IconCross, c(Reset), msg)
}

// Warn prints a yellow warning message.
func Warn(msg string) {
	fmt.Fprintf(os.Stderr, "  %s%s%s  %s\n", c(Yellow), IconWarn, c(Reset), msg)
}

// Info prints a blue info message.
func Info(msg string) {
	fmt.Fprintf(os.Stderr, "  %s%s%s %s\n", c(Cyan), IconInfo, c(Reset), msg)
}

// Step prints a dim step.
func Step(msg string) {
	fmt.Fprintf(os.Stderr, "  %s%s%s %s\n", c(Blue), IconDot, c(Reset), msg)
}

// ──────────────────────────────────────────────
// Files
// ──────────────────────────────────────────────

// FileCreated notifies a created file.
func FileCreated(path string) {
	fmt.Fprintf(os.Stderr, "  %s%s%s %s%s%s %s\n",
		c(Green), IconCheck, c(Reset),
		c(Dim), T("init.created"), c(Reset),
		path)
}

// FileSkipped notifies a skipped file.
func FileSkipped(path string) {
	fmt.Fprintf(os.Stderr, "  %s%s%s %s%s%s %s\n",
		c(Dim), "○", c(Reset),
		c(Dim), T("init.exists"), c(Reset),
		path)
}

// FileWouldCreate notifies a dry-run file.
func FileWouldCreate(path string) {
	fmt.Fprintf(os.Stderr, "  %s%s%s %s%s%s %s\n",
		c(Yellow), IconArrow, c(Reset),
		c(Dim), T("init.would_create"), c(Reset),
		path)
}

// ──────────────────────────────────────────────
// Results
// ──────────────────────────────────────────────

// ResultBox prints a colored result box.
func ResultBox(decision string, score int, summary string) {
	fmt.Fprintln(os.Stderr)

	if decision == "pass" {
		fmt.Fprintf(os.Stderr, "  %s%s ╭──────────────────────────────────────╮ %s\n", c(Green), c(Bold), c(Reset))
		fmt.Fprintf(os.Stderr, "  %s%s │  %s %-33s│ %s\n", c(Green), c(Bold), IconCheck, T("decision.pass")+"   Score: "+fmt.Sprintf("%d/100", score), c(Reset))
		fmt.Fprintf(os.Stderr, "  %s%s ╰──────────────────────────────────────╯ %s\n", c(Green), c(Bold), c(Reset))
	} else {
		fmt.Fprintf(os.Stderr, "  %s%s ╭──────────────────────────────────────╮ %s\n", c(Red), c(Bold), c(Reset))
		fmt.Fprintf(os.Stderr, "  %s%s │  %s %-33s│ %s\n", c(Red), c(Bold), IconCross, T("decision.fail")+"   Score: "+fmt.Sprintf("%d/100", score), c(Reset))
		fmt.Fprintf(os.Stderr, "  %s%s ╰──────────────────────────────────────╯ %s\n", c(Red), c(Bold), c(Reset))
	}

	if summary != "" {
		fmt.Fprintf(os.Stderr, "  %s%s%s\n", c(Dim), summary, c(Reset))
	}
	fmt.Fprintln(os.Stderr)
}

// ──────────────────────────────────────────────
// Severity tags
// ──────────────────────────────────────────────

// SeverityTag returns a colored severity badge.
func SeverityTag(severity string) string {
	label := T("severity." + severity)
	switch severity {
	case "critical":
		return fmt.Sprintf("%s%s %s %s", c(BgRed+Bold), c(White), label, c(Reset))
	case "high":
		return fmt.Sprintf("%s%s%s%s", c(Bold+Red), "● ", label, c(Reset))
	case "medium":
		return fmt.Sprintf("%s%s%s%s", c(Yellow), "● ", label, c(Reset))
	default:
		return fmt.Sprintf("%s%s%s%s", c(Cyan), "● ", label, c(Reset))
	}
}

// ──────────────────────────────────────────────
// Dividers / Spacing
// ──────────────────────────────────────────────

// Divider prints a thin separator.
func Divider() {
	fmt.Fprintf(os.Stderr, "\n  %s%s%s\n", c(Dim), strings.Repeat("─", 44), c(Reset))
}

// Newline prints a blank line.
func Newline() {
	fmt.Fprintln(os.Stderr)
}

// Hint prints a helpful tip with a star icon.
func Hint(msg string) {
	fmt.Fprintf(os.Stderr, "  %s%s %s%s\n", c(Dim), IconStar, msg, c(Reset))
}

// ──────────────────────────────────────────────
// Section
// ──────────────────────────────────────────────

// SectionTitle prints a bold section title.
func SectionTitle(title string) {
	fmt.Fprintf(os.Stderr, "  %s%s%s\n\n", c(Bold), title, c(Reset))
}
