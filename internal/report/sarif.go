package report

import (
	"encoding/json"

	"guard/internal/model"
)

// SARIF types for the 2.1.0 spec subset used by GitHub Code Scanning.

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name            string      `json:"name"`
	InformationURI  string      `json:"informationUri"`
	SemanticVersion string      `json:"semanticVersion"`
	Rules           []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string       `json:"id"`
	ShortDescription sarifMessage `json:"shortDescription"`
	DefaultConfig    sarifConfig  `json:"defaultConfiguration"`
}

type sarifConfig struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID    string           `json:"ruleId"`
	Level     string           `json:"level"`
	Message   sarifMessage     `json:"message"`
	Locations []sarifLocation  `json:"locations,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

// SARIF converts a Guard report to SARIF 2.1.0 format.
func SARIF(r *model.Report) ([]byte, error) {
	rulesMap := map[string]sarifRule{}
	var results []sarifResult

	for _, f := range r.Findings {
		if f.Muted {
			continue
		}
		if _, exists := rulesMap[f.RuleID]; !exists {
			rulesMap[f.RuleID] = sarifRule{
				ID:               f.RuleID,
				ShortDescription: sarifMessage{Text: f.Title},
				DefaultConfig:    sarifConfig{Level: sarifLevel(f.Severity)},
			}
		}

		result := sarifResult{
			RuleID:  f.RuleID,
			Level:   sarifLevel(f.Severity),
			Message: sarifMessage{Text: f.Message},
		}

		if f.File != "" {
			loc := sarifLocation{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: f.File},
				},
			}
			if f.Line > 0 {
				loc.PhysicalLocation.Region = &sarifRegion{StartLine: f.Line}
			}
			result.Locations = []sarifLocation{loc}
		}

		results = append(results, result)
	}

	var rules []sarifRule
	for _, rule := range rulesMap {
		rules = append(rules, rule)
	}

	log := sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{
				Driver: sarifDriver{
					Name:            "guard",
					InformationURI:  "https://github.com/user/guard",
					SemanticVersion: r.Version,
					Rules:           rules,
				},
			},
			Results: results,
		}},
	}

	return json.MarshalIndent(log, "", "  ")
}

func sarifLevel(s model.Severity) string {
	switch s {
	case model.SeverityCritical, model.SeverityHigh:
		return "error"
	case model.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}
