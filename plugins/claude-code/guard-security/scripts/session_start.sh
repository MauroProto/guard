#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

main() {
  local wrapper
  wrapper="$(guard_plugin_wrapper)"
  if [[ ! -x "$wrapper" ]]; then
    echo "Guard plugin wrapper is missing or not executable."
    exit 0
  fi

  local root
  if ! root="$(guard_detect_repo_root)"; then
    echo "Guard plugin: no repository root detected for this session."
    exit 0
  fi

  local data_dir
  data_dir="$(guard_plugin_data_dir)"
  : > "$(guard_plugin_state_file)"

  if [[ "${GUARD_PLUGIN_DRY_RUN:-0}" == "1" ]]; then
    echo "DRY_RUN session_start repo=${root} data=${data_dir}"
    exit 0
  fi

  if ! "$wrapper" version >/dev/null 2>&1; then
    echo "Guard plugin: Guard CLI is not available in PATH and GUARD_BIN is unset."
    exit 0
  fi

  local has_policy="no"
  local has_workspace="no"
  local has_lockfile="no"
  [[ -f "$root/.guard/policy.yaml" ]] && has_policy="yes"
  [[ -f "$root/pnpm-workspace.yaml" ]] && has_workspace="yes"
  [[ -f "$root/pnpm-lock.yaml" ]] && has_lockfile="yes"
  echo "Guard plugin ready: repo=${root} policy=${has_policy} workspace=${has_workspace} lockfile=${has_lockfile} mode=${GUARD_PLUGIN_MODE:-balanced}"
}

main "$@"
