package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"strings"

	"github.com/MauroProto/guard/internal/baseline"
	"github.com/MauroProto/guard/internal/config"
	"github.com/MauroProto/guard/internal/engine"
	"github.com/MauroProto/guard/internal/rules"
)

func runExplain(args []string) error {
	fs := flag.NewFlagSet("explain", flag.ContinueOnError)
	root := fs.String("root", ".", "repository root")
	configPath := fs.String("config", "", "path to Guard policy")
	format := fs.String("format", "terminal", "terminal|json")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("%w: %v", ErrUsage, err)
	}
	if fs.NArg() != 1 {
		return usageError("explain requires exactly one rule ID or fingerprint")
	}

	target := fs.Arg(0)
	if spec, ok := rules.Get(target); ok {
		return renderExplainRule(*format, spec)
	}

	cfg, err := config.Load(*root, *configPath)
	if err != nil {
		return err
	}

	rep, err := engine.ScanRepo(context.Background(), *root, cfg, &engine.ScanOptions{})
	if err == nil {
		for _, finding := range rep.Findings {
			finding.Normalize()
			if finding.Fingerprint == target {
				return renderExplainFinding(*format, map[string]any{
					"type":        "finding",
					"fingerprint": finding.Fingerprint,
					"rule_id":     finding.RuleID,
					"title":       finding.Title,
					"message":     finding.Message,
					"file":        finding.File,
					"line":        finding.Line,
					"confidence":  finding.Confidence,
					"evidence":    finding.Evidence,
				})
			}
		}
	}

	if baselineFile, loadErr := baseline.Load(baseline.Path(*root, cfg)); loadErr == nil {
		for _, entry := range baselineFile.Entries {
			if entry.Fingerprint != target {
				continue
			}
			return renderExplainFinding(*format, map[string]any{
				"type":        "baseline-entry",
				"fingerprint": entry.Fingerprint,
				"rule_id":     entry.RuleID,
				"title":       entry.Title,
				"message":     entry.Message,
				"file":        entry.File,
				"line":        entry.Line,
				"confidence":  entry.Confidence,
			})
		}
	}

	return usageError("unknown rule ID or fingerprint: " + target)
}

func renderExplainRule(format string, spec rules.Spec) error {
	payload := map[string]any{
		"type":             "rule",
		"rule_id":          spec.ID,
		"default_severity": spec.DefaultSeverity,
		"confidence":       spec.Confidence,
		"description":      spec.Description,
		"rationale":        spec.Rationale,
		"evidence":         spec.Evidence,
		"remediation":      spec.Remediation,
	}
	return renderExplainFinding(format, payload)
}

func renderExplainFinding(format string, payload map[string]any) error {
	switch format {
	case "json":
		out, err := json.MarshalIndent(payload, "", "  ")
		if err != nil {
			return err
		}
		fmt.Print(string(out))
		return nil
	default:
		var b strings.Builder
		if ruleID, ok := payload["rule_id"].(string); ok {
			fmt.Fprintf(&b, "Rule: %s\n", ruleID)
		}
		if typ, ok := payload["type"].(string); ok {
			fmt.Fprintf(&b, "Type: %s\n", typ)
		}
		if fingerprint, ok := payload["fingerprint"].(string); ok && fingerprint != "" {
			fmt.Fprintf(&b, "Fingerprint: %s\n", fingerprint)
		}
		if title, ok := payload["title"].(string); ok && title != "" {
			fmt.Fprintf(&b, "Title: %s\n", title)
		}
		if description, ok := payload["description"].(string); ok && description != "" {
			fmt.Fprintf(&b, "Description: %s\n", description)
		}
		if rationale, ok := payload["rationale"].(string); ok && rationale != "" {
			fmt.Fprintf(&b, "Why: %s\n", rationale)
		}
		if message, ok := payload["message"].(string); ok && message != "" {
			fmt.Fprintf(&b, "Message: %s\n", message)
		}
		if evidence, ok := payload["evidence"]; ok && evidence != nil {
			fmt.Fprintf(&b, "Evidence: %v\n", evidence)
		}
		if remediation, ok := payload["remediation"].(string); ok && remediation != "" {
			fmt.Fprintf(&b, "Remediation: %s\n", remediation)
		}
		if confidence, ok := payload["confidence"]; ok {
			fmt.Fprintf(&b, "Confidence: %v\n", confidence)
		}
		if file, ok := payload["file"].(string); ok && file != "" {
			fmt.Fprintf(&b, "File: %s\n", file)
		}
		if line, ok := payload["line"].(int); ok && line > 0 {
			fmt.Fprintf(&b, "Line: %d\n", line)
		}
		fmt.Print(b.String())
		return nil
	}
}
