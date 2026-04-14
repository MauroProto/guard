#!/usr/bin/env bash

guard_hook_script() {
  local script_dir
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  printf '%s\n' "$script_dir/guard_hook.py"
}

run_guard_hook() {
  local subcommand="$1"
  shift || true
  exec python3 "$(guard_hook_script)" "$subcommand" "$@"
}
