#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

main() {
  local command_text
  command_text="$(guard_collect_command "$@")"
  command_text="${command_text//$'\n'/ }"
  if [[ -z "$command_text" ]]; then
    exit 0
  fi

  case "$command_text" in
    pnpm\ add*|pnpm\ up*|pnpm\ install*|pnpm\ remove*|npm\ install*|npm\ update*|npm\ uninstall*)
      guard_set_scope_status "deps" "pending"
      echo "Guard noted a dependency mutation command. Run a focused dependency review after it completes."
      ;;
    corepack\ use*)
      guard_set_scope_status "workspace" "pending"
      echo "Guard noted a package manager/workspace mutation command. Review workspace posture after it completes."
      ;;
  esac
}

main "$@"
