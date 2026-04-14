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

with open(hooks_json, "r", encoding="utf-8") as fh:
    hooks = json.load(fh)

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

print("plugin structure OK")
PY
