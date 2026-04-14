package baseline

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/MauroProto/guard/internal/config"
	"github.com/MauroProto/guard/internal/model"
)

type Entry struct {
	Fingerprint string         `json:"fingerprint"`
	RuleID      string         `json:"rule_id"`
	Severity    model.Severity `json:"severity"`
	Package     string         `json:"package,omitempty"`
	Title       string         `json:"title"`
	Message     string         `json:"message,omitempty"`
	File        string         `json:"file,omitempty"`
	Line        int            `json:"line,omitempty"`
	Confidence  float64        `json:"confidence,omitempty"`
}

type File struct {
	SchemaVersion string    `json:"schemaVersion"`
	Tool          string    `json:"tool"`
	RecordedAt    time.Time `json:"recordedAt"`
	Entries       []Entry   `json:"entries"`
}

func Path(root string, cfg *config.Config) string {
	if cfg != nil && cfg.Baseline.Path != "" {
		if filepath.IsAbs(cfg.Baseline.Path) {
			return cfg.Baseline.Path
		}
		return filepath.Join(root, filepath.FromSlash(cfg.Baseline.Path))
	}
	return filepath.Join(root, ".guard", "baseline.json")
}

func Load(path string) (*File, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var file File
	if err := json.Unmarshal(b, &file); err != nil {
		return nil, err
	}
	if file.Entries == nil {
		file.Entries = []Entry{}
	}
	if file.SchemaVersion == "" {
		file.SchemaVersion = "1"
	}
	if file.Tool == "" {
		file.Tool = "guard"
	}
	return &file, nil
}

func Save(path string, findings []model.Finding, now time.Time) error {
	file := &File{
		SchemaVersion: "1",
		Tool:          "guard",
		RecordedAt:    now.UTC(),
		Entries:       make([]Entry, 0, len(findings)),
	}
	for _, finding := range findings {
		if finding.Muted {
			continue
		}
		finding.Normalize()
		file.Entries = append(file.Entries, Entry{
			Fingerprint: finding.Fingerprint,
			RuleID:      finding.RuleID,
			Severity:    finding.Severity,
			Package:     finding.Package,
			Title:       finding.Title,
			Message:     finding.Message,
			File:        finding.File,
			Line:        finding.Line,
			Confidence:  finding.Confidence,
		})
	}
	sort.Slice(file.Entries, func(i, j int) bool {
		return file.Entries[i].Fingerprint < file.Entries[j].Fingerprint
	})
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	out, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, out, 0o644)
}

func Index(file *File) map[string]Entry {
	out := map[string]Entry{}
	if file == nil {
		return out
	}
	for _, entry := range file.Entries {
		out[entry.Fingerprint] = entry
	}
	return out
}

func FilterFindings(findings []model.Finding, file *File) []model.Finding {
	if file == nil {
		return findings
	}
	index := Index(file)
	filtered := make([]model.Finding, 0, len(findings))
	for _, finding := range findings {
		finding.Normalize()
		if _, ok := index[finding.Fingerprint]; ok {
			continue
		}
		filtered = append(filtered, finding)
	}
	return filtered
}
