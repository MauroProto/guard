#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MARKETPLACE_JSON="$REPO_ROOT/.claude-plugin/marketplace.json"
PLUGIN_ROOT="$REPO_ROOT/plugins/claude-code/guard-security"
PLUGIN_JSON="$PLUGIN_ROOT/.claude-plugin/plugin.json"
HOOKS_JSON="$PLUGIN_ROOT/hooks/hooks.json"

[[ -f "$MARKETPLACE_JSON" ]] || { echo "missing $MARKETPLACE_JSON" >&2; exit 1; }
[[ -f "$PLUGIN_JSON" ]] || { echo "missing $PLUGIN_JSON" >&2; exit 1; }
[[ -f "$HOOKS_JSON" ]] || { echo "missing $HOOKS_JSON" >&2; exit 1; }
[[ -x "$PLUGIN_ROOT/bin/guard-plugin" ]] || { echo "wrapper is not executable: $PLUGIN_ROOT/bin/guard-plugin" >&2; exit 1; }

python3 - "$REPO_ROOT" "$MARKETPLACE_JSON" "$PLUGIN_ROOT" "$PLUGIN_JSON" "$HOOKS_JSON" <<'PY'
import json
import os
import sys

repo_root, marketplace_json, plugin_root, plugin_json, hooks_json = sys.argv[1:6]

with open(marketplace_json, "r", encoding="utf-8") as fh:
    marketplace = json.load(fh)

for key in ("name", "owner", "plugins"):
    if key not in marketplace:
        raise SystemExit(f"marketplace.json is missing required field: {key}")

match = None
for plugin_entry in marketplace["plugins"]:
    if plugin_entry.get("name") == "guard":
        match = plugin_entry
        break
if match is None:
    raise SystemExit("marketplace.json does not declare guard")

source = match.get("source", "")
if not source:
    raise SystemExit("guard marketplace entry is missing source")
resolved_source = os.path.normpath(os.path.join(repo_root, source))
if resolved_source != plugin_root:
    raise SystemExit(
        f"guard marketplace source points to {resolved_source}, expected {plugin_root}"
    )

with open(plugin_json, "r", encoding="utf-8") as fh:
    plugin = json.load(fh)

required = ["name", "version", "description", "author"]
for key in required:
    if key not in plugin:
        raise SystemExit(f"plugin.json is missing required field: {key}")

required_skills = [
    "skills/scan-contextual/SKILL.md",
    "skills/review-dependencies/SKILL.md",
    "skills/workflow-audit/SKILL.md",
    "skills/approve-build-guided/SKILL.md",
    "skills/explain-findings/SKILL.md",
]
for rel in required_skills:
    path = os.path.join(plugin_root, rel)
    if not os.path.isfile(path):
        raise SystemExit(f"missing skill file: {path}")

required_agents = [
    "agents/dependency-reviewer.md",
    "agents/workflow-security-reviewer.md",
    "agents/policy-reviewer.md",
]
for rel in required_agents:
    path = os.path.join(plugin_root, rel)
    if not os.path.isfile(path):
        raise SystemExit(f"missing agent file: {path}")

required_support = [
    os.path.join(plugin_root, "scripts", "guard_hook.py"),
    os.path.join(repo_root, "testdata", "plugin-hooks", "session_start.json"),
    os.path.join(repo_root, "testdata", "plugin-hooks", "cwd_changed.json"),
    os.path.join(repo_root, "testdata", "plugin-hooks", "file_changed.json"),
    os.path.join(repo_root, "testdata", "plugin-hooks", "pre_bash.json"),
    os.path.join(repo_root, "testdata", "plugin-hooks", "post_write.json"),
    os.path.join(repo_root, "testdata", "plugin-hooks", "post_bash.json"),
    os.path.join(repo_root, "testdata", "plugin-hooks", "stop.json"),
]
for path in required_support:
    if not os.path.isfile(path):
        raise SystemExit(f"missing plugin support file: {path}")

with open(hooks_json, "r", encoding="utf-8") as fh:
    hooks = json.load(fh)

required_events = {"SessionStart", "CwdChanged", "FileChanged", "PreToolUse", "PostToolUse", "Stop"}
missing_events = sorted(required_events - set(hooks.get("hooks", {})))
if missing_events:
    raise SystemExit(f"hooks.json is missing events: {', '.join(missing_events)}")

for event, entries in hooks.get("hooks", {}).items():
    for entry in entries:
        for hook in entry.get("hooks", []):
            command = hook.get("command", "")
            if "${CLAUDE_PLUGIN_ROOT}/" not in command:
                raise SystemExit(f"{event} hook does not reference CLAUDE_PLUGIN_ROOT: {command}")
            rel = command.split("${CLAUDE_PLUGIN_ROOT}/", 1)[1]
            target = os.path.join(plugin_root, rel)
            if not os.path.isfile(target):
                raise SystemExit(f"{event} hook references missing script: {target}")
            if not os.access(target, os.X_OK):
                raise SystemExit(f"{event} hook script is not executable: {target}")

pre_bash_ifs = []
post_bash_ifs = []
post_bash_async = False
post_write_async = False
for entry in hooks["hooks"].get("PreToolUse", []):
    if entry.get("matcher") == "Bash":
        pre_bash_ifs.extend(hook.get("if", "") for hook in entry.get("hooks", []))
for entry in hooks["hooks"].get("PostToolUse", []):
    if entry.get("matcher") == "Write|Edit":
        post_write_async = any(hook.get("async") for hook in entry.get("hooks", []))
    if entry.get("matcher") == "Bash":
        post_bash_async = any(hook.get("async") for hook in entry.get("hooks", []))
        post_bash_ifs.extend(hook.get("if", "") for hook in entry.get("hooks", []))

expected_ifs = {
    "Bash(pnpm add*)",
    "Bash(pnpm up*)",
    "Bash(pnpm install*)",
    "Bash(pnpm remove*)",
    "Bash(npm install*)",
    "Bash(npm update*)",
    "Bash(npm uninstall*)",
    "Bash(corepack use*)",
    "Bash(claude plugins marketplace add*)",
    "Bash(claude plugins install*)",
    "Bash(claude mcp add*)",
    "Bash(codex plugins marketplace add*)",
    "Bash(codex plugins install*)",
    "Bash(codex mcp add*)",
    "Bash(codex skills install*)",
    "Bash(npx skills add*)",
    "Bash(gemini extensions install*)",
    "Bash(curl*bash*)",
    "Bash(curl*sh*)",
    "Bash(curl*zsh*)",
    "Bash(wget*bash*)",
    "Bash(wget*sh*)",
    "Bash(wget*zsh*)",
    "Bash(bash*curl*)",
    "Bash(sh*curl*)",
    "Bash(zsh*curl*)",
    "Bash(bash*wget*)",
    "Bash(sh*wget*)",
    "Bash(zsh*wget*)",
}
if missing := sorted(expected_ifs - set(pre_bash_ifs)):
    raise SystemExit("PreToolUse Bash is missing command filters: " + ", ".join(missing))
if missing := sorted(expected_ifs - set(post_bash_ifs)):
    raise SystemExit("PostToolUse Bash is missing command filters: " + ", ".join(missing))
if not post_write_async:
    raise SystemExit("PostToolUse Write|Edit hook must be async")
if not post_bash_async:
    raise SystemExit("PostToolUse Bash hook must be async")

print("plugin structure OK")
PY

if command -v claude >/dev/null 2>&1; then
  echo "running official Claude validator"
  claude plugins validate "$REPO_ROOT"
  claude plugins validate "$PLUGIN_ROOT"
else
  echo "warning: claude CLI not found; skipping official plugin validation" >&2
fi
