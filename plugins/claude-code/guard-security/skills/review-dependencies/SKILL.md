---
name: review-dependencies
description: Use this skill when package.json, pnpm-lock.yaml, or dependency mutation commands changed the supply-chain surface and Guard should review dependency risk.
version: 0.2.1
---

# Review Dependencies

Use this skill when dependency files changed or Claude is about to mutate dependencies through `pnpm` or `npm`.

## Workflow

1. Run `guard scan --scope deps --files <package.json/pnpm-lock.yaml paths> --format json`.
2. If the change already exists on git refs and needs deeper review, suggest `guard review-pr`.
3. Call out:
   - pending build approvals,
   - OSV findings,
   - dependency posture regressions,
   - lockfile-related blocking findings.
4. If a package needs install/build approval, guide the user toward `guard approve-build <pkg> --importer <path> --version <version>`.

## Guardrails

- Do not auto-approve builds.
- Do not hide findings behind broad exceptions.
- Keep the review scoped to changed dependency surfaces unless the user asks for a full scan.
