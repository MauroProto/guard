package templates

import "embed"

//go:embed *.yml *.md
var fs embed.FS

// GuardCI returns the guard-ci.yml workflow template.
func GuardCI() ([]byte, error) {
	return fs.ReadFile("guard-ci.yml")
}

// Agents returns the AGENTS.md template.
func Agents() ([]byte, error) {
	return fs.ReadFile("AGENTS.md")
}

// Claude returns the CLAUDE.md template.
func Claude() ([]byte, error) {
	return fs.ReadFile("CLAUDE.md")
}
