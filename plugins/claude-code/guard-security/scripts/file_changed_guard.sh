#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

main() {
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

  local scopes=("policy" "workspace" "deps" "workflows")
  local scope
  for scope in "${scopes[@]}"; do
    local matches=()
    while IFS= read -r line; do
      [[ -z "$line" ]] && continue
      matches+=("$line")
    done < <(guard_scope_files "$scope" "${files[@]}")
    if [[ "${#matches[@]}" -gt 0 ]]; then
      guard_set_scope_status "$scope" "pending"
      echo "Guard pending review: ${scope}"
    fi
  done
}

main "$@"
