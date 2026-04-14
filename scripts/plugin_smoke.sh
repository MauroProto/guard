#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLUGIN_ROOT="$REPO_ROOT/plugins/claude-code/guard-security"
FIXTURES_DIR="$REPO_ROOT/testdata/plugin-hooks"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

GUARD_BIN_PATH="$TMPDIR/guard"
TEST_REPO="$TMPDIR/repo"
TRANSCRIPT_PATH="$TMPDIR/transcript.jsonl"
STATE_GLOB="$TMPDIR/plugin-data/repos"

mkdir -p "$TEST_REPO/.github/workflows" "$TEST_REPO/.guard" "$TEST_REPO/packages/app"
cat > "$TEST_REPO/package.json" <<'EOF'
{"name":"smoke-app","version":"1.0.0"}
EOF
cat > "$TEST_REPO/pnpm-lock.yaml" <<'EOF'
lockfileVersion: '9.0'
packages: {}
EOF
cat > "$TEST_REPO/pnpm-workspace.yaml" <<'EOF'
packages:
  - packages/*
strictDepBuilds: true
blockExoticSubdeps: true
trustPolicy: no-downgrade
minimumReleaseAge: 1440
EOF
cat > "$TEST_REPO/.guard/policy.yaml" <<'EOF'
version: 1
EOF
cat > "$TEST_REPO/.github/workflows/ci.yml" <<'EOF'
name: CI
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@main
EOF
cat > "$TEST_REPO/packages/app/package.json" <<'EOF'
{"name":"app-package","version":"1.0.0"}
EOF

cd "$REPO_ROOT"
go build -o "$GUARD_BIN_PATH" ./cmd/guard

export GUARD_BIN="$GUARD_BIN_PATH"
export CLAUDE_PLUGIN_ROOT="$PLUGIN_ROOT"
export CLAUDE_PLUGIN_DATA="$TMPDIR/plugin-data"
export GUARD_MIN_VERSION=0.2.0

git -C "$TEST_REPO" init -q
git -C "$TEST_REPO" config user.name "Smoke Test"
git -C "$TEST_REPO" config user.email "smoke@example.com"
git -C "$TEST_REPO" add .
git -C "$TEST_REPO" commit -qm "initial"
touch "$TRANSCRIPT_PATH"

render_fixture() {
  local template="$1"
  shift
  python3 - "$template" "$@" <<'PY'
from pathlib import Path
import sys

text = Path(sys.argv[1]).read_text(encoding="utf-8")
for pair in sys.argv[2:]:
    key, value = pair.split("=", 1)
    text = text.replace(f"__{key}__", value)
print(text)
PY
}

run_hook() {
  local script="$1"
  local fixture="$2"
  shift 2
  render_fixture "$fixture" "$@" | "$script"
}

json_assert() {
  local payload="$1"
  local expression="$2"
  python3 - "$expression" <<'PY' <<<"$payload"
import json
import sys

expr = sys.argv[1]
payload = sys.stdin.read().strip()
data = json.loads(payload) if payload else None
namespace = {"data": data}
if not eval(expr, {"__builtins__": {}}, namespace):
    raise SystemExit(f"assertion failed: {expr}\npayload={payload}")
PY
}

state_path() {
  find "$STATE_GLOB" -name state.json | head -n1
}

state_assert() {
  local expression="$1"
  python3 - "$expression" "$(state_path)" <<'PY'
import json
import sys

expr, path = sys.argv[1:3]
with open(path, "r", encoding="utf-8") as fh:
    data = json.load(fh)
namespace = {"data": data}
if not eval(expr, {"__builtins__": {}}, namespace):
    raise SystemExit(f"state assertion failed: {expr}\nstate={json.dumps(data, indent=2)}")
PY
}

"$PLUGIN_ROOT/bin/guard-plugin" version >/dev/null

SESSION_OUT="$(run_hook "$PLUGIN_ROOT/scripts/session_start.sh" "$FIXTURES_DIR/session_start.json" \
  CWD="$TEST_REPO" TRANSCRIPT="$TRANSCRIPT_PATH" SESSION_ID="sess-1")"
json_assert "$SESSION_OUT" 'data["hookSpecificOutput"]["hookEventName"] == "SessionStart"'
json_assert "$SESSION_OUT" '"balanced mode" in data["hookSpecificOutput"]["additionalContext"]'

CWD_OUT="$(run_hook "$PLUGIN_ROOT/scripts/cwd_changed_guard.sh" "$FIXTURES_DIR/cwd_changed.json" \
  CWD="$TEST_REPO" OLD_CWD="$TMPDIR" NEW_CWD="$TEST_REPO" TRANSCRIPT="$TRANSCRIPT_PATH" SESSION_ID="sess-1")"
json_assert "$CWD_OUT" 'any(path.endswith("/pnpm-lock.yaml") for path in data["watchPaths"])'
json_assert "$CWD_OUT" 'any(path.endswith("/packages/app/package.json") for path in data["watchPaths"])'
json_assert "$CWD_OUT" 'any(path.endswith("/.github/workflows/ci.yml") for path in data["watchPaths"])'

FILE_OUT="$(run_hook "$PLUGIN_ROOT/scripts/file_changed_guard.sh" "$FIXTURES_DIR/file_changed.json" \
  CWD="$TEST_REPO" FILE_PATH="$TEST_REPO/packages/app/package.json" EVENT="change" TRANSCRIPT="$TRANSCRIPT_PATH" SESSION_ID="sess-1")"
json_assert "$FILE_OUT" 'isinstance(data["watchPaths"], list) and len(data["watchPaths"]) >= 3'
state_assert 'data["scopes"]["deps"]["pending"] is True'
state_assert 'data["scopes"]["deps"]["last_trigger"] == "file_changed"'

PRE_OBSERVE="$(GUARD_PLUGIN_MODE=observe run_hook "$PLUGIN_ROOT/scripts/pre_bash_guard.sh" "$FIXTURES_DIR/pre_bash.json" \
  CWD="$TEST_REPO" TRANSCRIPT="$TRANSCRIPT_PATH" SESSION_ID="sess-1" COMMAND="pnpm add sharp")"
json_assert "$PRE_OBSERVE" '"permissionDecision" not in data["hookSpecificOutput"]'

PRE_BALANCED="$(GUARD_PLUGIN_MODE=balanced run_hook "$PLUGIN_ROOT/scripts/pre_bash_guard.sh" "$FIXTURES_DIR/pre_bash.json" \
  CWD="$TEST_REPO" TRANSCRIPT="$TRANSCRIPT_PATH" SESSION_ID="sess-1" COMMAND="pnpm add sharp")"
json_assert "$PRE_BALANCED" 'data["hookSpecificOutput"]["permissionDecision"] == "ask"'

POST_WRITE="$(GUARD_PLUGIN_MODE=balanced run_hook "$PLUGIN_ROOT/scripts/post_write_guard.sh" "$FIXTURES_DIR/post_write.json" \
  CWD="$TEST_REPO" TRANSCRIPT="$TRANSCRIPT_PATH" SESSION_ID="sess-1" FILE_PATH="$TEST_REPO/.github/workflows/ci.yml")"
json_assert "$POST_WRITE" '"workflow" in data["additionalContext"] or "workflows" in data["additionalContext"]'
state_assert 'data["scopes"]["workflows"]["status"] == "blocking"'
state_assert 'data["scopes"]["workflows"]["needs_attention"] is True'

cat > "$TEST_REPO/package.json" <<'EOF'
{"name":"smoke-app","version":"1.0.1"}
EOF

POST_BASH="$(GUARD_PLUGIN_MODE=balanced run_hook "$PLUGIN_ROOT/scripts/post_bash_guard.sh" "$FIXTURES_DIR/post_bash.json" \
  CWD="$TEST_REPO" TRANSCRIPT="$TRANSCRIPT_PATH" SESSION_ID="sess-1" COMMAND="pnpm install")"
json_assert "$POST_BASH" '"deps" in data["additionalContext"]'
state_assert 'data["scopes"]["deps"]["status"] in {"warning", "blocking"}'

python3 - "$(state_path)" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as fh:
    data = json.load(fh)
data["scopes"]["deps"]["status"] = "blocking"
data["scopes"]["deps"]["blocking_count"] = 1
data["scopes"]["deps"]["warning_count"] = max(data["scopes"]["deps"]["warning_count"], 1)
with open(path, "w", encoding="utf-8") as fh:
    json.dump(data, fh, indent=2, sort_keys=True)
    fh.write("\n")
PY

PRE_STRICT="$(GUARD_PLUGIN_MODE=strict run_hook "$PLUGIN_ROOT/scripts/pre_bash_guard.sh" "$FIXTURES_DIR/pre_bash.json" \
  CWD="$TEST_REPO" TRANSCRIPT="$TRANSCRIPT_PATH" SESSION_ID="sess-1" COMMAND="pnpm add sharp")"
json_assert "$PRE_STRICT" 'data["hookSpecificOutput"]["permissionDecision"] == "deny"'

STOP_BALANCED="$(GUARD_PLUGIN_MODE=balanced run_hook "$PLUGIN_ROOT/scripts/stop_summary.sh" "$FIXTURES_DIR/stop.json" \
  CWD="$TEST_REPO" TRANSCRIPT="$TRANSCRIPT_PATH" SESSION_ID="sess-1" LAST_ASSISTANT="done" STOP_HOOK_ACTIVE="false")"
json_assert "$STOP_BALANCED" 'data["decision"] == "block"'

STOP_ACTIVE="$(GUARD_PLUGIN_MODE=balanced run_hook "$PLUGIN_ROOT/scripts/stop_summary.sh" "$FIXTURES_DIR/stop.json" \
  CWD="$TEST_REPO" TRANSCRIPT="$TRANSCRIPT_PATH" SESSION_ID="sess-1" LAST_ASSISTANT="done" STOP_HOOK_ACTIVE="true")"
[[ -z "$STOP_ACTIVE" ]]

echo "plugin smoke OK"
