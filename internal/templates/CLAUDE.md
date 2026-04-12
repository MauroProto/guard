# CLAUDE.md — AI Assistant Constraints

This repository enforces supply chain controls through Guard and pnpm.

## Rules

- Do not disable `strictDepBuilds`.
- Do not disable `blockExoticSubdeps`.
- Do not reduce `minimumReleaseAge` without explicit approval.
- Do not weaken `trustPolicy` without explicit approval.
- Do not add unpinned third-party GitHub Actions (must use full SHA).
- Do not remove or modify `.guard/policy.yaml` without review.
- When adding dependencies, verify they are published on npm and not from git URLs.
- Run `guard scan` after any dependency or workflow change.
