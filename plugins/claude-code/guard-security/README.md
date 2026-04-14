# Guard Security Plugin for Claude Code

This plugin keeps the Guard CLI as the deterministic security engine and adds a Claude Code layer that reacts to dependency, workflow, workspace, and policy changes.

## Design

- Guard CLI remains the source of truth for scanning, CI, SARIF, JSON, and headless automation.
- The plugin only orchestrates focused Guard commands inside Claude Code.
- V1 is `balanced` by default:
  - no full scans on every event,
  - no auto-fix from hooks,
  - no Bash blocking by default,
  - no binary bootstrap magic.

## Layout

- `.claude-plugin/plugin.json`: plugin metadata
- `bin/guard-plugin`: wrapper that resolves the Guard CLI from `GUARD_BIN` or `PATH`
- `hooks/hooks.json`: Claude Code hook wiring
- `scripts/`: hook implementations and helpers
- `skills/`: contextual Guard workflows
- `agents/`: specialized review roles

## Installation

1. Install Guard on the system or build it locally.
2. Install it as a persistent plugin from the Guard marketplace:

```bash
claude plugins marketplace add MauroProto/guard
claude plugins install guard@guard
```

This leaves the plugin available globally in Claude Code for the current user.

3. For a one-off session, you can still load the plugin directly:

```bash
claude --plugin-dir /absolute/path/to/guard/plugins/claude-code/guard-security
```

4. If Guard is not on `PATH`, export `GUARD_BIN`:

```bash
export GUARD_BIN=/absolute/path/to/guard
```

## Hook behavior

- `SessionStart`
  - verifies Guard availability,
  - detects repo root and key files,
  - initializes light state.
- `FileChanged`
  - marks `deps`, `workflows`, `workspace`, or `policy` as pending review.
- `PostToolUse` on `Write|Edit`
  - runs focused Guard scans in JSON mode for affected surfaces.
- `PreToolUse` on `Bash`
  - watches dependency mutation commands and marks dependency review as pending.
- `Stop`
  - summarizes pending or blocking Guard scopes.

## Development

From the Guard repo root:

```bash
make plugin-check
make plugin-smoke
```

## Troubleshooting

- `guard plugin requires Guard CLI in PATH or GUARD_BIN`
  - install Guard or set `GUARD_BIN`.
- No output from hooks
  - confirm the session is inside a repo with `package.json`, `pnpm-workspace.yaml`, `.guard/policy.yaml`, or `.git`.
- Want to inspect commands without executing scans
  - set `GUARD_PLUGIN_DRY_RUN=1`.
