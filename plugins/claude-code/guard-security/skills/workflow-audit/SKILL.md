---
name: workflow-audit
description: Use this skill when GitHub Actions workflows or CODEOWNERS changed and Claude should run a focused Guard workflow audit.
version: 0.2.3
---

# Workflow Audit

Use this skill when a workflow file or `CODEOWNERS` changed.

## Workflow

1. Run `guard scan --scope workflows --files <workflow-or-codeowners-paths> --format json`.
2. Explain findings in terms of trust boundaries:
   - unpinned actions,
   - broad token permissions,
   - `pull_request_target` risk,
   - publish/release posture,
   - missing `CODEOWNERS`.
3. Offer concrete remediation steps in the edited workflow.

## Guardrails

- Do not rewrite unrelated jobs.
- Avoid speculative fixes when Guard did not report a finding.
- Keep the review focused on the changed workflow files unless the user requests a full repo audit.
