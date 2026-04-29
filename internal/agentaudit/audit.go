package agentaudit

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/MauroProto/guard/internal/engine"
	"github.com/MauroProto/guard/internal/model"
	"github.com/MauroProto/guard/internal/rules"
)

const categoryAgent = "agent"

var secretNamePattern = regexp.MustCompile(`(?i)(api[_-]?key|token|secret|password|passwd|credential|private[_-]?key)`)

type Options struct {
	Root   string
	Home   string
	Now    time.Time
	FailOn string
}

func Audit(ctx context.Context, opts Options) (*model.Report, error) {
	_ = ctx
	root := opts.Root
	if root == "" {
		root = "."
	}
	absRoot, err := filepath.Abs(root)
	if err == nil {
		root = absRoot
	}
	home := opts.Home
	if home == "" {
		home, _ = os.UserHomeDir()
	}

	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	report := &model.Report{
		SchemaVersion: "1",
		Tool:          "guard-agent-audit",
		Version:       engine.Version,
		Root:          root,
		Timestamp:     now,
		Decision:      "pass",
	}

	for _, path := range configPaths(root, home) {
		auditMCPConfig(report, path, home)
	}
	for _, dir := range skillRoots(root, home) {
		auditSkills(report, dir)
	}
	for _, dir := range pluginRoots(root, home) {
		auditPluginHooks(report, dir)
	}

	applyFailOn(report, opts.FailOn)
	report.Recompute()
	return report, nil
}

func configPaths(root, home string) []string {
	values := []string{
		filepath.Join(root, ".claude", "settings.json"),
		filepath.Join(root, ".claude", "settings.local.json"),
		filepath.Join(root, ".mcp.json"),
	}
	if home != "" {
		values = append(values,
			filepath.Join(home, ".claude", "settings.json"),
			filepath.Join(home, ".claude", "settings.local.json"),
			filepath.Join(home, ".config", "claude-code", "settings.json"),
		)
	}
	return uniqueExistingFiles(values)
}

func skillRoots(root, home string) []string {
	values := []string{
		filepath.Join(root, ".claude", "skills"),
	}
	if home != "" {
		values = append(values,
			filepath.Join(home, ".claude", "skills"),
			filepath.Join(home, ".codex", "skills"),
			filepath.Join(home, ".agents", "skills"),
		)
	}
	return uniqueExistingDirs(values)
}

func pluginRoots(root, home string) []string {
	values := []string{
		filepath.Join(root, ".claude", "plugins"),
	}
	if home != "" {
		values = append(values,
			filepath.Join(home, ".claude", "plugins"),
		)
	}
	return uniqueExistingDirs(values)
}

func auditMCPConfig(report *model.Report, path, home string) {
	data, err := readJSON(path)
	if err != nil {
		report.AddFinding(model.Finding{
			RuleID:      "agent.config.unreadable",
			Severity:    model.SeverityLow,
			Category:    categoryAgent,
			Title:       "Agent configuration could not be parsed",
			Message:     fmt.Sprintf("Guard could not parse %s as JSON.", filepath.Base(path)),
			Remediation: "Fix the agent configuration syntax and rerun `guard agent audit`.",
			File:        slash(path),
			Evidence: map[string]any{
				"error": err.Error(),
			},
		})
		return
	}
	for _, server := range findMCPServers(data, path) {
		auditMCPServer(report, server, home)
	}
}

type mcpServer struct {
	Name    string
	File    string
	Command string
	Args    []string
	Env     map[string]string
}

func auditMCPServer(report *model.Report, server mcpServer, home string) {
	parts := commandParts(server.Command, server.Args)
	commandText := strings.Join(parts, " ")
	if isRemoteBootstrap(commandText) {
		report.AddFinding(agentFinding(
			"agent.mcp.remote_bootstrap",
			model.SeverityHigh,
			"Registered MCP runs remote bootstrap code",
			fmt.Sprintf("MCP server %q downloads code and executes it inline.", server.Name),
			"Inspect the script first or replace the MCP with a pinned local binary/package.",
			server.File,
			map[string]any{"surface": "mcp", "name": server.Name},
		))
	}

	if runnerPackageNeedsPin(parts) {
		report.AddFinding(agentFinding(
			"agent.mcp.unpinned_npx",
			model.SeverityHigh,
			"Registered MCP uses an unpinned package runner",
			fmt.Sprintf("MCP server %q uses npx/uvx/bunx without a pinned package version.", server.Name),
			"Pin the MCP package version or install a trusted local binary.",
			server.File,
			map[string]any{"surface": "mcp", "name": server.Name, "command": redactedCommand(parts)},
		))
	}

	if exposesBroadFilesystem(parts, home) {
		report.AddFinding(agentFinding(
			"agent.mcp.filesystem_broad",
			model.SeverityHigh,
			"Registered MCP exposes a broad filesystem scope",
			fmt.Sprintf("MCP server %q appears to expose the filesystem root or home directory.", server.Name),
			"Restrict the MCP filesystem scope to the specific project directories it needs.",
			server.File,
			map[string]any{"surface": "mcp", "name": server.Name},
		))
	}

	for key, value := range server.Env {
		if secretNamePattern.MatchString(key) && isInlineSecretValue(value) {
			report.AddFinding(agentFinding(
				"agent.mcp.inline_secret_env",
				model.SeverityHigh,
				"Registered MCP contains an inline secret-looking environment value",
				fmt.Sprintf("MCP server %q sets %s directly in config.", server.Name, key),
				"Move the value to an environment variable or secret manager reference.",
				server.File,
				map[string]any{"surface": "mcp", "name": server.Name, "env_key": key},
			))
		}
	}
}

func commandParts(command string, args []string) []string {
	var parts []string
	parts = append(parts, strings.Fields(command)...)
	parts = append(parts, args...)
	return parts
}

func auditSkills(report *model.Report, root string) {
	walkNamedFiles(root, "SKILL.md", func(path string) {
		body, err := os.ReadFile(path)
		if err != nil {
			return
		}
		text := string(body)
		if isRemoteBootstrap(text) {
			report.AddFinding(agentFinding(
				"agent.skill.remote_bootstrap",
				model.SeverityHigh,
				"Skill contains remote bootstrap instructions",
				"A skill file contains a curl/wget-to-shell pattern.",
				"Inspect the skill source and replace inline bootstrap commands with pinned, reviewable install steps.",
				path,
				map[string]any{"surface": "skill", "root": slash(root)},
			))
		}
	})
}

func auditPluginHooks(report *model.Report, root string) {
	walkNamedFiles(root, "hooks.json", func(path string) {
		body, err := os.ReadFile(path)
		if err != nil {
			return
		}
		text := string(body)
		if isRemoteBootstrap(text) {
			report.AddFinding(agentFinding(
				"agent.plugin.remote_bootstrap",
				model.SeverityHigh,
				"Plugin hook contains remote bootstrap execution",
				"A plugin hook command contains a curl/wget-to-shell pattern.",
				"Disable or remove the plugin until the hook command is inspected and replaced with a pinned local command.",
				path,
				map[string]any{"surface": "plugin", "root": slash(root)},
			))
		}
	})
}

func readJSON(path string) (any, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var data any
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, err
	}
	return data, nil
}

func findMCPServers(value any, file string) []mcpServer {
	var servers []mcpServer
	var walk func(any)
	walk = func(current any) {
		switch node := current.(type) {
		case map[string]any:
			for key, child := range node {
				if key == "mcpServers" {
					if serverMap, ok := child.(map[string]any); ok {
						for name, raw := range serverMap {
							if data, ok := raw.(map[string]any); ok {
								servers = append(servers, mcpServer{
									Name:    name,
									File:    file,
									Command: stringField(data, "command"),
									Args:    stringList(data["args"]),
									Env:     stringMap(data["env"]),
								})
							}
						}
					}
					continue
				}
				walk(child)
			}
		case []any:
			for _, child := range node {
				walk(child)
			}
		}
	}
	walk(value)
	sort.Slice(servers, func(i, j int) bool {
		if servers[i].File == servers[j].File {
			return servers[i].Name < servers[j].Name
		}
		return servers[i].File < servers[j].File
	})
	return servers
}

func stringField(data map[string]any, key string) string {
	value, _ := data[key].(string)
	return value
}

func stringList(value any) []string {
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		if value, ok := item.(string); ok {
			out = append(out, value)
		}
	}
	return out
}

func stringMap(value any) map[string]string {
	items, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	out := map[string]string{}
	for key, item := range items {
		if value, ok := item.(string); ok {
			out[key] = value
		}
	}
	return out
}

func runnerPackageNeedsPin(parts []string) bool {
	if len(parts) == 0 {
		return false
	}
	runner := filepath.Base(parts[0])
	if runner != "npx" && runner != "uvx" && runner != "bunx" {
		return false
	}
	pkg := firstRunnerPackage(parts[1:])
	return pkg != "" && !isPackagePinned(pkg)
}

func firstRunnerPackage(args []string) string {
	for _, arg := range args {
		if arg == "" || arg == "--" {
			continue
		}
		if strings.HasPrefix(arg, "-") {
			continue
		}
		return strings.Trim(arg, `"'`)
	}
	return ""
}

func isPackagePinned(spec string) bool {
	if spec == "" || strings.Contains(spec, "://") || strings.HasPrefix(spec, ".") || strings.HasPrefix(spec, "/") {
		return true
	}
	if strings.HasPrefix(spec, "@") {
		slash := strings.Index(spec, "/")
		return slash > 0 && strings.LastIndex(spec, "@") > slash
	}
	return strings.LastIndex(spec, "@") > 0
}

func exposesBroadFilesystem(parts []string, home string) bool {
	joined := strings.Join(parts, " ")
	if !strings.Contains(joined, "server-filesystem") {
		return false
	}
	for _, part := range parts[1:] {
		cleaned := strings.Trim(part, `"'`)
		if cleaned == "/" || cleaned == "~" {
			return true
		}
		if home != "" {
			abs, err := filepath.Abs(cleaned)
			if err == nil && abs == home {
				return true
			}
		}
	}
	return false
}

func isInlineSecretValue(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	if strings.HasPrefix(value, "$") || strings.HasPrefix(value, "${") || strings.HasPrefix(value, "env:") {
		return false
	}
	lower := strings.ToLower(value)
	return lower != "redacted" && lower != "***" && lower != "<redacted>"
}

func isRemoteBootstrap(text string) bool {
	lower := strings.ToLower(text)
	if regexp.MustCompile(`\b(curl|wget)\b[^|\n\r]*\|\s*(sh|bash|zsh)\b`).FindString(lower) != "" {
		return true
	}
	if regexp.MustCompile(`\b(sh|bash|zsh)\b[^\n\r]*(<\(|\$\()[^\n\r]*(curl|wget)\b`).FindString(lower) != "" {
		return true
	}
	return false
}

func walkNamedFiles(root, name string, fn func(string)) {
	_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		if entry.Name() == name {
			fn(path)
		}
		return nil
	})
}

func agentFinding(ruleID string, severity model.Severity, title, message, remediation, file string, evidence map[string]any) model.Finding {
	finding := model.Finding{
		RuleID:      ruleID,
		Severity:    severity,
		Category:    categoryAgent,
		Title:       title,
		Message:     message,
		Remediation: remediation,
		File:        slash(file),
		Evidence:    evidence,
	}
	rules.ApplyDefaults(&finding)
	return finding
}

func redactedCommand(parts []string) string {
	if len(parts) > 6 {
		parts = append(append([]string{}, parts[:6]...), "...")
	}
	return strings.Join(parts, " ")
}

func applyFailOn(report *model.Report, failOn string) {
	if failOn == "" {
		failOn = "high"
	}
	if strings.EqualFold(failOn, "none") {
		return
	}
	threshold := model.SeverityRank(model.ParseSeverity(strings.ToLower(failOn)))
	for i := range report.Findings {
		if model.SeverityRank(report.Findings[i].Severity) >= threshold {
			report.Findings[i].Blocking = true
		}
	}
}

func uniqueExistingFiles(values []string) []string {
	return uniqueExisting(values, false)
}

func uniqueExistingDirs(values []string) []string {
	return uniqueExisting(values, true)
}

func uniqueExisting(values []string, wantDir bool) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		if value == "" {
			continue
		}
		path, err := filepath.Abs(value)
		if err != nil {
			path = value
		}
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		if wantDir != info.IsDir() || seen[path] {
			continue
		}
		seen[path] = true
		out = append(out, path)
	}
	sort.Strings(out)
	return out
}

func slash(path string) string {
	return filepath.ToSlash(path)
}
