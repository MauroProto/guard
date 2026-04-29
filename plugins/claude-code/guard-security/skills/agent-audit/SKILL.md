---
name: agent-audit
description: Use this skill when the user wants Guard to audit installed MCP servers, skills, plugins, or hooks for risky agent-tooling configuration.
version: 0.2.3
---

# Agent Audit

Use this skill when the user wants to review the installed agent tooling surface, including MCP servers, skills, plugins, and hooks.

## Workflow

1. Run `guard agent audit --format json`.
2. Summarize blocking findings first, then warnings.
3. Call out:
   - MCPs that use unpinned package runners such as `npx`, `uvx`, or `bunx`
   - broad filesystem MCP scopes
   - inline secret-looking environment values
   - skill or plugin hook remote bootstrap patterns such as `curl ... | sh`
4. Recommend the smallest safe action: pin a version, narrow a path, move a secret to an environment reference, disable a hook, or inspect source before trusting it.

## Guardrails

- Do not uninstall, disable, or edit MCPs/plugins/skills without an explicit user request.
- Do not print secret values; only identify the config key and file.
- Do not treat every unfamiliar MCP or skill as malicious. Explain the concrete signal Guard found.
