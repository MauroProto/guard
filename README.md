# Guard

Supply chain security for `pnpm` repositories and GitHub Actions.

Guard helps teams answer one question before a dependency or CI change lands:

> Can we trust this change?

It combines:

- repository posture checks,
- dependency and lockfile review,
- workflow hardening,
- policy validation and exceptions,
- machine-readable output for CI and automation.

Links:

- [Changelog](./CHANGELOG.md)
- [Releases](https://github.com/MauroProto/guard/releases)

<p align="center">
  <img src="https://img.shields.io/badge/go-%3E%3D1.23-blue" alt="Go 1.23+">
  <img src="https://img.shields.io/badge/pnpm-supported-orange" alt="pnpm">
  <img src="https://img.shields.io/badge/claude%20code-plugin-available-6f42c1" alt="Claude Code plugin">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="MIT License">
</p>

## Install

| Target | Install |
| --- | --- |
| Claude Code | `claude plugins marketplace add MauroProto/guard && claude plugins install guard@guard` |
| Guard CLI (Go) | `go install github.com/MauroProto/guard/cmd/guard@latest` |
| Guard CLI (shell) | `curl -fsSL https://raw.githubusercontent.com/MauroProto/guard/main/install.sh \| sh` |
| From source | `git clone https://github.com/MauroProto/guard.git && cd guard && make install` |

If the Claude Code plugin cannot find the `guard` binary in `PATH`, set:

```bash
export GUARD_BIN=/absolute/path/to/guard
```

## What Guard ships

Guard is a hybrid product:

- **Guard CLI** stays first-class for CI, SARIF, JSON, headless scans, `review-pr`, `baseline`, and `policy lint`.
- **Claude Code plugin** adds focused, contextual Guard runs inside edit sessions without replacing the CLI.

The plugin is distributed from this repository through `.claude-plugin/marketplace.json`, and the Claude Code plugin itself lives at:

```text
plugins/claude-code/guard-security
```

## Quick start

```bash
guard init
guard scan
guard fix
guard baseline record
```

For a PR or branch review:

```bash
guard review-pr
guard review-pr --base origin/main --head HEAD --format markdown
guard explain review.diff.install_script.added
```

For focused scans:

```bash
guard scan --scope workflows --format json
guard scan --scope deps --files package.json,pnpm-lock.yaml --format json
guard scan --scope policy --files .guard/policy.yaml --format json
guard scan --changed-files --format json
```

## Claude Code plugin

The plugin is designed to be useful, not noisy.

When enabled, it reacts to the right moments:

- `SessionStart`
  - verifies Guard availability,
  - detects repo root and key files,
  - initializes light session state.
- `FileChanged`
  - marks `deps`, `workflows`, `workspace`, or `policy` as pending review.
- `PostToolUse` on `Write|Edit`
  - runs focused Guard scans in JSON mode for affected surfaces.
- `PreToolUse` on `Bash`
  - watches dependency mutation commands such as `pnpm add`, `pnpm up`, `pnpm install`, `npm install`, and `corepack use`.
- `Stop`
  - summarizes pending or blocking Guard scopes.

V1 behavior is intentionally balanced:

- no full scans on every event,
- no auto-fix from hooks,
- no blanket Bash blocking,
- no dependence on paths outside the installed plugin bundle.

### One-off local plugin testing

```bash
claude --plugin-dir /absolute/path/to/guard/plugins/claude-code/guard-security
```

## Commands

| Command | Alias | Description |
| --- | --- | --- |
| `guard scan` | `guard s` | Scan the repository for security issues |
| `guard fix` | `guard f` | Apply safe local remediations |
| `guard init` | `guard i` | Create or patch a secure baseline |
| `guard ci` | `guard c` | Strict scan mode for CI pipelines |
| `guard diff` | `guard d` | Compare two package versions for risk signals |
| `guard review-pr` | `guard review` | Review dependency and workflow changes between git refs |
| `guard approve` | `guard ab` | Approve a package that needs build scripts |
| `guard baseline record` | - | Record the current finding set as baseline debt |
| `guard explain` | - | Explain a rule ID or a finding fingerprint |
| `guard policy lint` | - | Validate policy/config semantics and deprecated fields |

## What it checks

### Repository posture

- missing `pnpm-lock.yaml`
- missing `packageManager` in `package.json`
- missing `engines.node`

### pnpm hardening

- `minimumReleaseAge` missing or too low
- `blockExoticSubdeps` disabled
- `strictDepBuilds` disabled
- `trustPolicy` not set to `no-downgrade`
- unapproved build scripts in `allowBuilds`

### GitHub Actions

- actions not pinned to full commit SHA
- missing or overly broad `permissions`
- missing `CODEOWNERS`
- risky `pull_request_target` patterns
- privileged publish workflows without attestations

### Dependency review

- new install scripts
- suspicious remote fetch or command execution patterns
- new binary files
- obfuscation signals
- sensitive path access like `.env`, `.ssh`, `.npmrc`
- new OSV advisories
- trust regressions surfaced by `review-pr`

## Output formats

```bash
guard scan --format terminal
guard scan --format json
guard scan --format sarif
guard scan --format markdown
```

All machine-readable outputs are schema-versioned and suitable for plugin or CI consumption.

## CI example

```yaml
name: Guard
on: [pull_request]
permissions:
  contents: read
jobs:
  guard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<SHA>
      - uses: actions/setup-go@<SHA>
        with:
          go-version: "1.23"
      - run: go install github.com/MauroProto/guard/cmd/guard@latest
      - run: guard ci --format sarif --output guard.sarif
      - uses: github/codeql-action/upload-sarif@<SHA>
        if: always()
        with:
          sarif_file: guard.sarif
```

## Development

```bash
git clone https://github.com/MauroProto/guard.git
cd guard
make build
make test
make vet
make plugin-check
make plugin-smoke
```

Validate the Claude Code plugin and marketplace locally:

```bash
claude plugins validate .
claude plugins marketplace add .
claude plugins install guard@guard
```

## Roadmap

Guard is intentionally focused today:

- `pnpm` workspaces
- GitHub Actions
- Claude Code integration
- deterministic CLI and CI usage

Likely next steps:

- deeper `review-lockfile` workflows,
- richer provenance and trusted publishing signals,
- private registries and `.npmrc` awareness,
- optional MCP integration,
- broader multi-agent packaging.

## License

MIT
