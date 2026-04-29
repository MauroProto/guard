---
name: explain-findings
description: Use this skill when Guard emitted findings and Claude should explain the rule, evidence, blocking status, and next safe step.
version: 0.2.3
---

# Explain Findings

Use this skill when Guard emitted findings and Claude needs to translate them into a concise decision.

## Workflow

1. Prefer `guard explain <rule-id-or-fingerprint>`.
2. If you already have JSON output, quote the exact finding title, rule ID, severity, and evidence.
3. Explain:
   - what changed,
   - why Guard cares,
   - whether it blocks,
   - what the next safe step is.

## Guardrails

- Do not paraphrase away the blocking status.
- Keep explanations grounded in Guard output, not speculation.
