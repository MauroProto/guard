# Changelog

All notable changes to Guard will be documented in this file.

The format is based on Keep a Changelog and this project follows SemVer.

## [0.2.1] - 2026-04-15

### Changed

- Claude Code plugin version bumped to `0.2.1` so marketplace updates are visible immediately in clients
- plugin hook runtime now watches external plugin, skill, MCP, and extension install commands with low-noise `ask` behavior in `balanced`
- plugin strict mode now denies only clear remote bootstrap commands that download code and execute it inline, instead of broadly blocking unfamiliar agent tooling

### Fixed

- plugin update detection in Claude Code now has a fresh marketplace/plugin version to upgrade against
- plugin smoke and structure checks now cover agent-install and remote-bootstrap command filters consistently
- plugin state and reporting now persist focused risk for external agent-tooling commands without breaking normal MCP or skill usage

## [0.2.0] - 2026-04-14

### Added

- Claude Code plugin and marketplace distribution from this repository
- focused `guard scan` modes with `--scope`, `--files`, and `--changed-files`
- `guard review-pr` for dependency and workflow review between git refs
- `guard baseline record` for suppressing accepted debt by fingerprint
- `guard explain` for rule IDs and finding fingerprints
- `guard policy lint` for validating policy/config issues and deprecated fields

### Changed

- README rewritten around the hybrid Guard CLI + Claude Code product model
- plugin installation flow simplified to `claude plugins marketplace add MauroProto/guard && claude plugins install guard@guard`
- workflow discovery now honors configured workflow paths
- package exceptions and build approvals use more precise matching and scoped approvals
- JSON and machine-readable outputs are more stable for CI and plugin consumption
- GitHub Actions auditing now includes trust-boundary checks for publish workflows and risky triggers

### Fixed

- baseline recording now preserves existing OSV debt when OSV scanning is enabled
- baseline fingerprints no longer churn on harmless line-number-only edits
- policy lint no longer fails the default workflow path in repositories without workflows
- npm registry errors now surface real upstream failures instead of misleading cache misses
- clean JSON outputs emit empty arrays instead of `null` where appropriate

## [0.1.0] - 2026-04-13

### Added

- initial Guard CLI release for `pnpm` supply chain hardening
- `scan`, `fix`, `init`, `ci`, and `diff` commands
- basic GitHub Actions auditing and SARIF/JSON output
