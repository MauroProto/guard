#!/usr/bin/env bash

guard_plugin_root() {
  if [[ -n "${CLAUDE_PLUGIN_ROOT:-}" ]]; then
    printf '%s\n' "$CLAUDE_PLUGIN_ROOT"
    return 0
  fi
  cd "$(dirname "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd
}

guard_plugin_data_dir() {
  local base
  base="${CLAUDE_PLUGIN_DATA:-$(guard_plugin_root)/.plugin-data}"
  local dir="${base%/}/guard"
  mkdir -p "$dir/reports"
  printf '%s\n' "$dir"
}

guard_plugin_state_file() {
  printf '%s\n' "$(guard_plugin_data_dir)/scope-status.tsv"
}

guard_plugin_report_path() {
  local scope="$1"
  printf '%s\n' "$(guard_plugin_data_dir)/reports/${scope}.json"
}

guard_plugin_wrapper() {
  printf '%s\n' "$(guard_plugin_root)/bin/guard-plugin"
}

guard_detect_repo_root() {
  local candidate
  for candidate in "${GUARD_REPO_ROOT:-}" "${CLAUDE_WORKSPACE_ROOT:-}" "${CLAUDE_PROJECT_DIR:-}" "${PWD:-}"; do
    if [[ -z "$candidate" || ! -d "$candidate" ]]; then
      continue
    fi
    if [[ -f "$candidate/pnpm-workspace.yaml" || -f "$candidate/.guard/policy.yaml" || -f "$candidate/package.json" || -d "$candidate/.git" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

guard_collect_paths() {
  if [[ "$#" -gt 0 ]]; then
    printf '%s\n' "$@"
    return 0
  fi
  if [[ -n "${CLAUDE_CHANGED_FILES:-}" ]]; then
    printf '%s' "$CLAUDE_CHANGED_FILES" | tr ',' '\n'
    return 0
  fi
  if [[ ! -t 0 ]]; then
    cat
  fi
}

guard_collect_command() {
  if [[ "$#" -gt 0 ]]; then
    printf '%s\n' "$*"
    return 0
  fi
  if [[ -n "${CLAUDE_TOOL_INPUT:-}" ]]; then
    printf '%s\n' "$CLAUDE_TOOL_INPUT"
    return 0
  fi
  if [[ ! -t 0 ]]; then
    cat
  fi
}

guard_normalize_paths() {
  python3 -c '
import os, sys

seen = set()
items = []
for raw in sys.stdin.read().splitlines():
    value = raw.strip()
    if not value:
        continue
    norm = os.path.normpath(value).replace("\\", "/")
    if norm in seen:
        continue
    seen.add(norm)
    items.append(norm)
items.sort()
for item in items:
    print(item)
'
}

guard_scope_matches_file() {
  local scope="$1"
  local file="$2"
  case "$scope" in
    workflows)
      [[ "$file" == CODEOWNERS || "$file" == ".github/CODEOWNERS" || "$file" == "docs/CODEOWNERS" || "$file" == */workflows/*.yml || "$file" == */workflows/*.yaml ]]
      ;;
    deps)
      [[ "$file" == "pnpm-lock.yaml" || "$(basename "$file")" == "package.json" ]]
      ;;
    workspace)
      [[ "$file" == "pnpm-workspace.yaml" ]]
      ;;
    policy)
      [[ "$file" == ".guard/policy.yaml" ]]
      ;;
    *)
      return 1
      ;;
  esac
}

guard_scope_files() {
  local scope="$1"
  shift || true
  local file
  for file in "$@"; do
    if guard_scope_matches_file "$scope" "$file"; then
      printf '%s\n' "$file"
    fi
  done
}

guard_set_scope_status() {
  local scope="$1"
  local status="$2"
  local state_file
  state_file="$(guard_plugin_state_file)"
  touch "$state_file"
  awk -F '\t' -v scope="$scope" '$1 != scope' "$state_file" > "${state_file}.tmp"
  printf '%s\t%s\n' "$scope" "$status" >> "${state_file}.tmp"
  mv "${state_file}.tmp" "$state_file"
}

guard_pending_summary() {
  local state_file
  state_file="$(guard_plugin_state_file)"
  [[ -f "$state_file" ]] || return 0
  awk -F '\t' '$2 == "pending" || $2 == "blocking" {print $1 "\t" $2}' "$state_file"
}

guard_json_status() {
  local file="$1"
  local kind="$2"
  python3 - "$file" "$kind" <<'PY'
import json
import sys

path, kind = sys.argv[1], sys.argv[2]
with open(path, "r", encoding="utf-8") as fh:
    data = json.load(fh)

if kind == "policy":
    issues = data.get("issues") or []
    if any(issue.get("severity") == "error" for issue in issues):
        print("blocking")
    elif issues:
        print("warning")
    else:
        print("clean")
else:
    findings = data.get("findings") or []
    if any(f.get("blocking") and not f.get("muted") for f in findings):
        print("blocking")
    elif findings:
        print("warning")
    else:
        print("clean")
PY
}

guard_run_json() {
  local scope="$1"
  local root="$2"
  shift 2 || true
  local report_path
  report_path="$(guard_plugin_report_path "$scope")"
  local wrapper
  wrapper="$(guard_plugin_wrapper)"
  local files_csv=""
  if [[ "$#" -gt 0 ]]; then
    files_csv="$(IFS=,; printf '%s' "$*")"
  fi

  if [[ "${GUARD_PLUGIN_DRY_RUN:-0}" == "1" ]]; then
    printf 'DRY_RUN %s scan --root %s --scope %s --format json --no-color' "$wrapper" "$root" "$scope"
    if [[ -n "$files_csv" ]]; then
      printf ' --files %s' "$files_csv"
    fi
    printf '\n'
    return 0
  fi

  local output status
  set +e
  if [[ -n "$files_csv" ]]; then
    output="$("$wrapper" scan --root "$root" --scope "$scope" --format json --no-color --files "$files_csv")"
    status=$?
  else
    output="$("$wrapper" scan --root "$root" --scope "$scope" --format json --no-color)"
    status=$?
  fi
  set -e
  printf '%s\n' "$output" > "$report_path"
  local result
  result="$(guard_json_status "$report_path" scan)"
  guard_set_scope_status "$scope" "$result"
  if [[ "$result" != "clean" ]]; then
    printf 'Guard %s review: %s findings detected.\n' "$scope" "$result"
  fi
  return "$status"
}

guard_run_policy_lint() {
  local root="$1"
  local report_path
  report_path="$(guard_plugin_report_path "policy-lint")"
  local wrapper
  wrapper="$(guard_plugin_wrapper)"

  if [[ "${GUARD_PLUGIN_DRY_RUN:-0}" == "1" ]]; then
    printf 'DRY_RUN %s policy lint --root %s --format json --no-color\n' "$wrapper" "$root"
    return 0
  fi

  local output status
  set +e
  output="$("$wrapper" policy lint --root "$root" --format json --no-color)"
  status=$?
  set -e
  printf '%s\n' "$output" > "$report_path"
  local result
  result="$(guard_json_status "$report_path" policy)"
  guard_set_scope_status "policy" "$result"
  if [[ "$result" != "clean" ]]; then
    printf 'Guard policy review: %s issues detected.\n' "$result"
  fi
  return "$status"
}
