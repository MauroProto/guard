# Guard Plugin for Claude Code

Guard stays a CLI-first security tool. This plugin adds a Claude Code runtime that reacts to risky dependency, workflow, workspace, and policy events with focused scans and low-noise prompts.

## What it is

- `guard` CLI remains the deterministic engine for CI, JSON, SARIF, `scan`, `diff`, `review-pr`, `policy lint`, and headless automation.
- The Claude Code plugin is an orchestration layer.
- Hooks consume the real Claude hook protocol: JSON on stdin and JSON on stdout.
- The plugin uses focused `guard scan --scope ...` calls instead of full scans on every event.
- The plugin also watches high-risk agent bootstrap commands so docs-driven plugin, skill, or MCP installs do not execute blindly.
- The CLI can audit already-installed MCPs, skills, plugins, and hooks with `guard agent audit`.

## Installation

Install the marketplace and plugin:

```bash
claude plugins marketplace add MauroProto/guard
claude plugins install guard@guard
```

Reload plugins or restart Claude Code after installing.

Guard CLI still needs to be available on the machine:

```bash
go install github.com/MauroProto/guard/cmd/guard@latest
```

If Guard is not already on `PATH`, point the plugin at it explicitly:

```bash
export GUARD_BIN=/absolute/path/to/guard
```

For a one-off local session instead of a persistent install:

```bash
claude --plugin-dir /absolute/path/to/guard/plugins/claude-code/guard-security
```

## Modes

Set the mode with `GUARD_PLUGIN_MODE`.

### `observe`
- never blocks
- never asks for confirmation
- adds lightweight context when a risky command runs with blocking findings, pending review, or remote bootstrap risk

### `balanced` (default)
- optimized for day-to-day development
- asks before sensitive dependency/workspace commands only when Guard already has blocking findings or pending focused review for the relevant scope
- asks before external plugin, skill, MCP, or extension install commands
- asks before remote bootstrap commands that download code and execute it inline
- runs focused scans asynchronously after sensitive writes and dependency mutation commands
- `Stop` warns on fresh blocking results from sensitive changes but does not block the final response

### `strict`
- denies sensitive dependency/workspace commands when relevant blocking Guard results are already active
- denies remote bootstrap commands that download code and execute it inline
- asks when a focused review is still pending
- asks before external plugin, skill, MCP, or extension install commands
- blocks `Stop` on fresh blocking results and on critical pending review that has not been addressed yet

## What the plugin watches

The plugin maintains a dynamic watch list per repo and recomputes it when the working directory changes:

- `pnpm-lock.yaml`
- `pnpm-workspace.yaml`
- `.guard/policy.yaml`
- root `package.json`
- workspace `package.json` files discovered from `pnpm-workspace.yaml`
- `CODEOWNERS`, `.github/CODEOWNERS`, `docs/CODEOWNERS`
- workflow directories and workflow files from Guard policy `github.workflowPaths` or the default `.github/workflows`

## When it acts

### `SessionStart`
- detects the repo root
- verifies Guard CLI availability
- initializes per-repo JSON state
- adds one short context line to Claude

### `CwdChanged`
- recomputes dynamic `watchPaths`
- rehydrates repo state when you move into a different repo

### `FileChanged`
- marks the relevant scope as pending
- updates `watchPaths`
- does not run heavy scans

### `PreToolUse` for sensitive Bash commands
Commands covered in V1:

- `pnpm add`
- `pnpm up`
- `pnpm install`
- `pnpm remove`
- `npm install`
- `npm update`
- `npm uninstall`
- `corepack use`
- `claude plugins marketplace add`
- `claude plugins install`
- `claude mcp add`
- `codex plugins marketplace add`
- `codex plugins install`
- `codex mcp add`
- `codex skills install`
- `npx skills add`
- `gemini extensions install`
- common remote bootstrap patterns such as `curl ... | sh`, `wget ... | bash`, or `bash <(curl ...)`

This hook still does not run for generic Bash. It only intercepts dependency mutation commands, agent ecosystem install commands, and clear remote-bootstrap patterns.

### `PostToolUse` on `Write|Edit`
- async
- scans only the affected scope
- can review:
  - lockfile/package changes as `deps`
  - workflow and `CODEOWNERS` changes as `workflows`
  - `.guard/policy.yaml` as `policy`
  - `pnpm-workspace.yaml` as `workspace`

### `PostToolUse` on sensitive Bash
- async
- closes the loop after dependency/workspace mutation commands
- records focused agent-install or remote-bootstrap risk when those commands actually run
- uses `--changed-files` when possible to stay focused

### `Stop`
- does nothing in `observe`
- warns without blocking in `balanced`
- blocks in `strict` when fresh blocking results or critical pending reviews remain active

### Manual agent tooling audit

Run this when you want to inspect the current installed surface rather than only intercept new install commands:

```bash
guard agent audit --format json
```

The audit checks registered MCPs, local skills, plugin hooks, unpinned package runners, broad filesystem MCP scopes, inline secret-looking MCP env values, and remote bootstrap patterns.

## Runtime limits

Hook subprocesses have hard timeouts so a slow Guard CLI cannot hang the agent session:

- `GUARD_PLUGIN_VERSION_TIMEOUT_SECONDS`, default `2`
- `GUARD_PLUGIN_SCAN_TIMEOUT_SECONDS`, default `20`

When a scan times out or does not return JSON, the plugin records an error in
the per-repo state instead of reporting the scope as clean.

## What it does not do

- does not replace the Guard CLI
- does not auto-fix from hooks
- does not auto-approve build scripts or permissions
- does not run full scans on every change
- does not block generic Bash traffic
- does not kill MCPs, skills, or plugins just because they are unfamiliar
- does not claim to sandbox arbitrary repositories or all external tooling
- does not bootstrap binaries automatically

## Development

From the repo root:

```bash
make plugin-check
make plugin-smoke
```

`plugin-check` validates the marketplace/plugin structure and uses `claude plugins validate` when the Claude CLI is available.

`plugin-smoke` simulates real hook payloads over stdin JSON and verifies `SessionStart`, `CwdChanged`, `FileChanged`, `PreToolUse`, `PostToolUse`, and `Stop`.

## Troubleshooting

- `guard plugin requires Guard CLI in PATH or GUARD_BIN`
  - install Guard or set `GUARD_BIN`
- `guard plugin could not determine the Guard CLI version`
  - check that `guard version` runs correctly
- hook output seems ignored
  - reload plugins after installation or update
- plugin feels too strict
  - switch to `GUARD_PLUGIN_MODE=observe` or `GUARD_PLUGIN_MODE=balanced`
