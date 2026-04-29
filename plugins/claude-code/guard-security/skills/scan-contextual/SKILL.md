---
name: scan-contextual
description: Use this skill when dependency, workflow, workspace, or policy files changed and Claude needs a focused Guard scan instead of a full repository scan.
version: 0.2.3
---

# Scan Contextual

Use this skill when the current Claude Code session touched supply-chain-sensitive files and you need a focused Guard run instead of a full repository scan.

## When to use it

- `package.json` or `pnpm-lock.yaml` changed
- `pnpm-workspace.yaml` changed
- `.guard/policy.yaml` changed
- GitHub Actions workflows or `CODEOWNERS` changed

## Workflow

1. Prefer `guard scan --scope <scope> --files <repo-relative-paths> --format json`.
2. Use the narrowest scope that matches the files:
   - `deps`
   - `workspace`
   - `workflows`
   - `policy`
3. Only fall back to a full `guard scan` when the touched surface is unclear.
4. Summarize blocking findings first, then warnings.
5. Do not auto-run `guard fix` from this skill.

## Notes

- The plugin wrapper is `guard-plugin`.
- If there are no relevant files, say so and stop.
