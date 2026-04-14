#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

main() {
  local summary
  summary="$(guard_pending_summary)"
  if [[ -z "$summary" ]]; then
    exit 0
  fi
  echo "Guard summary before stop:"
  while IFS=$'\t' read -r scope status; do
    [[ -z "$scope" ]] && continue
    echo "  - ${scope}: ${status}"
  done <<<"$summary"
}

main "$@"
