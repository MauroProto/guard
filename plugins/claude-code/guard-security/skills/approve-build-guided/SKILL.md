---
name: approve-build-guided
description: Use this skill when Guard reports pending build approvals and the user wants a scoped, explicit approve-build workflow.
version: 0.2.2
---

# Approve Build Guided

Use this skill when Guard reports `pnpm.allowBuilds.unreviewed` and the user wants to approve a package deliberately.

## Workflow

1. Explain why the package currently needs approval.
2. Resolve the narrowest scope available:
   - package
   - importer
   - version
3. Prefer `guard approve-build <pkg> --importer <path> --version <version>`.
4. Ask for a reason if the approval is going to persist in policy.
5. After approval, rerun the focused dependency scan.

## Guardrails

- Do not approve without an explicit user request.
- Do not widen the exception beyond the resolved importer/version unless Guard could not determine them.
