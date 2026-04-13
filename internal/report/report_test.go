package report

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/MauroProto/guard/internal/model"
)

func fixtureReport() *model.Report {
	r := &model.Report{
		Tool:      "guard",
		Version:   "0.1.0",
		Root:      "/test",
		Timestamp: time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC),
		Decision:  "fail",
	}
	r.AddFinding(model.Finding{
		RuleID:      "test.high",
		Severity:    model.SeverityHigh,
		Category:    model.CategoryRepo,
		Title:       "Test high finding",
		Message:     "This is a high finding",
		Remediation: "Fix it",
		Blocking:    true,
	})
	r.AddFinding(model.Finding{
		RuleID:   "test.low",
		Severity: model.SeverityLow,
		Category: model.CategoryRepo,
		Title:    "Test low finding",
		Message:  "This is a low finding",
	})
	r.Score = 23
	return r
}

func TestJSONRoundTrip(t *testing.T) {
	rep := fixtureReport()
	b, err := JSON(rep)
	if err != nil {
		t.Fatalf("JSON marshal failed: %v", err)
	}

	var parsed model.Report
	if err := json.Unmarshal(b, &parsed); err != nil {
		t.Fatalf("JSON unmarshal failed: %v", err)
	}
	if parsed.Tool != "guard" {
		t.Fatalf("expected tool guard, got %s", parsed.Tool)
	}
	if len(parsed.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(parsed.Findings))
	}
	if parsed.Decision != "fail" {
		t.Fatalf("expected decision fail, got %s", parsed.Decision)
	}
}

func TestSARIFStructure(t *testing.T) {
	rep := fixtureReport()
	b, err := SARIF(rep)
	if err != nil {
		t.Fatalf("SARIF marshal failed: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(b, &parsed); err != nil {
		t.Fatalf("SARIF is not valid JSON: %v", err)
	}
	if parsed["version"] != "2.1.0" {
		t.Fatalf("expected SARIF version 2.1.0, got %v", parsed["version"])
	}
	runs, ok := parsed["runs"].([]any)
	if !ok || len(runs) != 1 {
		t.Fatal("expected exactly 1 run")
	}
	run := runs[0].(map[string]any)
	results := run["results"].([]any)
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	tool := run["tool"].(map[string]any)
	driver := tool["driver"].(map[string]any)
	if driver["informationUri"] != "https://github.com/MauroProto/guard" {
		t.Fatalf("expected canonical informationUri, got %v", driver["informationUri"])
	}
}

func TestSARIFEmptyCollectionsMarshalAsArrays(t *testing.T) {
	rep := &model.Report{
		Tool:      "guard",
		Version:   "dev",
		Root:      "/tmp/test",
		Timestamp: time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC),
		Decision:  "pass",
	}
	b, err := SARIF(rep)
	if err != nil {
		t.Fatalf("SARIF marshal failed: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(b, &parsed); err != nil {
		t.Fatalf("SARIF is not valid JSON: %v", err)
	}
	runs := parsed["runs"].([]any)
	run := runs[0].(map[string]any)
	if results, ok := run["results"].([]any); !ok || len(results) != 0 {
		t.Fatalf("expected results to be an empty array, got %#v", run["results"])
	}
	tool := run["tool"].(map[string]any)
	driver := tool["driver"].(map[string]any)
	if rules, ok := driver["rules"].([]any); !ok || len(rules) != 0 {
		t.Fatalf("expected rules to be an empty array, got %#v", driver["rules"])
	}
}

func TestJSONEmptyFindingsMarshalAsArray(t *testing.T) {
	rep := &model.Report{
		Tool:      "guard",
		Version:   "dev",
		Root:      "/tmp/test",
		Timestamp: time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC),
		Decision:  "pass",
	}
	b, err := JSON(rep)
	if err != nil {
		t.Fatalf("JSON marshal failed: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(b, &parsed); err != nil {
		t.Fatalf("JSON is not valid JSON: %v", err)
	}
	if findings, ok := parsed["findings"].([]any); !ok || len(findings) != 0 {
		t.Fatalf("expected findings to be an empty array, got %#v", parsed["findings"])
	}
}

func TestTerminalOutput(t *testing.T) {
	rep := fixtureReport()
	out := Terminal(rep, true) // no color
	if !strings.Contains(out, "Guard 0.1.0") {
		t.Fatal("expected version in terminal output")
	}
	if !strings.Contains(out, "FAIL") {
		t.Fatal("expected FAIL in terminal output")
	}
	if !strings.Contains(out, "test.high") {
		t.Fatal("expected test.high rule ID in output")
	}
}

func TestMarkdownOutput(t *testing.T) {
	rep := fixtureReport()
	out := Markdown(rep)
	if !strings.Contains(out, "## Guard Scan Report") {
		t.Fatal("expected markdown header")
	}
	if !strings.Contains(out, "`test.high`") {
		t.Fatal("expected test.high in markdown table")
	}
	if !strings.Contains(out, "### Remediation") {
		t.Fatal("expected remediation section")
	}
}
