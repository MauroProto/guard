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
	Target  Target   `json:"target"`
	Signals []Signal `json:"signals"`
	Score   int      `json:"score"`
	Summary string   `json:"summary"`
}

// PackageContents represents the expanded contents of a package tarball.
type PackageContents struct {
	PackageJSON map[string]any    // parsed package.json
	Files       map[string][]byte // relative path -> content
	FileList    []string          // sorted list of file paths
}

// Heuristic is a function that analyzes two package versions and returns signals.
type Heuristic func(from, to *PackageContents) []Signal
