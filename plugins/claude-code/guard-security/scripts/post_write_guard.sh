#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

main() {
  local root
  if ! root="$(guard_detect_repo_root)"; then
    exit 0
  fi

  local normalized
  normalized="$(guard_collect_paths "$@" | guard_normalize_paths)"
  if [[ -z "$normalized" ]]; then
    exit 0
  fi

  local files=()
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    files+=("$line")
  done <<<"$normalized"

  local policy_files=() deps_files=() workflow_files=() workspace_files=()
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    policy_files+=("$line")
  done < <(guard_scope_files policy "${files[@]}")
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    workspace_files+=("$line")
  done < <(guard_scope_files workspace "${files[@]}")
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    deps_files+=("$line")
  done < <(guard_scope_files deps "${files[@]}")
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    workflow_files+=("$line")
  done < <(guard_scope_files workflows "${files[@]}")

  if [[ "${#policy_files[@]}" -gt 0 ]]; then
    guard_run_policy_lint "$root" || true
    guard_run_json "policy" "$root" "${policy_files[@]}" || true
  fi
  if [[ "${#workspace_files[@]}" -gt 0 ]]; then
    guard_run_json "workspace" "$root" "${workspace_files[@]}" || true
  fi
  if [[ "${#deps_files[@]}" -gt 0 ]]; then
    guard_run_json "deps" "$root" "${deps_files[@]}" || true
  fi
  if [[ "${#workflow_files[@]}" -gt 0 ]]; then
    guard_run_json "workflows" "$root" "${workflow_files[@]}" || true
  fi
}

main "$@"
