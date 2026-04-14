package diff

import (
	"fmt"
	"strings"

	"github.com/MauroProto/guard/internal/model"
)

// Target holds the parsed diff target.
type Target struct {
	Package string `json:"package"`
	From    string `json:"from"`
	To      string `json:"to"`
}

// ParseTarget parses a string like "axios@1.7.9..1.8.0" into a Target.
func ParseTarget(s string) (*Target, error) {
	at := strings.LastIndex(s, "@")
	if at <= 0 || at == len(s)-1 {
		return nil, fmt.Errorf("invalid diff target %q: expected <pkg>@<from>..<to>", s)
	}
	name := s[:at]
	rangePart := s[at+1:]
	parts := strings.Split(rangePart, "..")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil, fmt.Errorf("invalid version range %q: expected <from>..<to>", rangePart)
	}
	return &Target{
		Package: name,
		From:    parts[0],
		To:      parts[1],
	}, nil
}

// Signal represents a single risk signal found during diff comparison.
type Signal struct {
	ID       string         `json:"id"`
	Severity model.Severity `json:"severity"`
	Title    string         `json:"title"`
	Message  string         `json:"message"`
	File     string         `json:"file,omitempty"`
	Line     int            `json:"line,omitempty"`
	Evidence map[string]any `json:"evidence,omitempty"`
}

// DiffResult holds the complete comparison between two package versions.
type DiffResult struct {
	SchemaVersion string   `json:"schemaVersion"`
	Target        Target   `json:"target"`
	Signals       []Signal `json:"signals"`
	Score         int      `json:"score"`
	Summary       string   `json:"summary"`
	Disabled      bool     `json:"disabled,omitempty"`
}

// PackageContents represents the expanded contents of a package tarball.
type PackageContents struct {
	PackageJSON map[string]any    // parsed package.json
	Files       map[string][]byte // relative path -> content
	FileList    []string          // sorted list of file paths
}

// Heuristic is a function that analyzes two package versions and returns signals.
type Heuristic func(from, to *PackageContents) []Signal

var knownSignalNames = map[string]string{
	"diff.install_script.added":          "diff.install_script.added",
	"install_script_added":               "diff.install_script.added",
	"diff.install_script.changed":        "diff.install_script.changed",
	"install_script_changed":             "diff.install_script.changed",
	"diff.remote_url.added":              "diff.remote_url.added",
	"remote_url_added":                   "diff.remote_url.added",
	"diff.binary.added":                  "diff.binary.added",
	"binary_added":                       "diff.binary.added",
	"diff.obfuscation.suspected":         "diff.obfuscation.suspected",
	"obfuscation_suspected":              "diff.obfuscation.suspected",
	"diff.sensitive_path_access.added":   "diff.sensitive_path_access.added",
	"sensitive_path_access_added":        "diff.sensitive_path_access.added",
	"diff.suspicious_api.added":          "diff.suspicious_api.added",
	"suspicious_api_added":               "diff.suspicious_api.added",
	"diff.structural.file_count_spike":   "diff.structural.file_count_spike",
	"structural_file_count_spike":        "diff.structural.file_count_spike",
	"diff.structural.shell_script_added": "diff.structural.shell_script_added",
	"structural_shell_script_added":      "diff.structural.shell_script_added",
}

func KnownSignalNames() map[string]bool {
	out := make(map[string]bool, len(knownSignalNames))
	for name := range knownSignalNames {
		out[name] = true
	}
	return out
}

func NormalizeSignalName(name string) string {
	if canonical, ok := knownSignalNames[name]; ok {
		return canonical
	}
	return name
}
