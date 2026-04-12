# AGENTS.md — Supply Chain Rules for Contributors

This repository enforces supply chain controls through Guard and pnpm.

## Rules

- Use **pnpm** as the only package manager. Do not use npm or yarn.
- Keep `pnpm-lock.yaml` committed and up to date.
- Prefer exact versions over ranges when possible.
- Do not add dependencies from git URLs or direct tarballs without security review.
- New releases must respect the configured `minimumReleaseAge` before installation.
- Changes to `.github/workflows/` require review from the security team or CODEOWNERS.
- Do not weaken Guard or pnpm security defaults without explicit approval.
- Run `guard scan` before submitting PRs that modify dependencies or workflows.
