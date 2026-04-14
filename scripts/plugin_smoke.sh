#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLUGIN_ROOT="$REPO_ROOT/plugins/claude-code/guard-security"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

GUARD_BIN_PATH="$TMPDIR/guard"
TEST_REPO="$TMPDIR/repo"

mkdir -p "$TEST_REPO/.github/workflows" "$TEST_REPO/.guard"
cat > "$TEST_REPO/package.json" <<'EOF'
{"name":"smoke-app"}
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

cd "$REPO_ROOT"
go build -o "$GUARD_BIN_PATH" ./cmd/guard

export GUARD_BIN="$GUARD_BIN_PATH"
export CLAUDE_PLUGIN_ROOT="$PLUGIN_ROOT"
export CLAUDE_PLUGIN_DATA="$TMPDIR/plugin-data"
export GUARD_REPO_ROOT="$TEST_REPO"
export GUARD_PLUGIN_DRY_RUN=1

"$PLUGIN_ROOT/bin/guard-plugin" version >/dev/null

SESSION_OUT="$("$PLUGIN_ROOT/scripts/session_start.sh")"
FILE_OUT="$("$PLUGIN_ROOT/scripts/file_changed_guard.sh" package.json .github/workflows/ci.yml .guard/policy.yaml)"
POST_OUT="$("$PLUGIN_ROOT/scripts/post_write_guard.sh" package.json .github/workflows/ci.yml .guard/policy.yaml)"
PRE_OUT="$("$PLUGIN_ROOT/scripts/pre_bash_guard.sh" "pnpm add sharp")"
STOP_OUT="$("$PLUGIN_ROOT/scripts/stop_summary.sh")"

grep -q "session_start" <<<"$SESSION_OUT"
grep -q "deps" <<<"$FILE_OUT"
grep -q "workflows" <<<"$FILE_OUT"
grep -q -- "--scope deps" <<<"$POST_OUT"
grep -q -- "--scope workflows" <<<"$POST_OUT"
grep -q -- "policy lint" <<<"$POST_OUT"
grep -q "dependency mutation command" <<<"$PRE_OUT"
grep -q "Guard summary before stop" <<<"$STOP_OUT"

echo "plugin smoke OK"
