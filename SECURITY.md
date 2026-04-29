# Security Policy

## Supported Versions

Security fixes are prepared for the latest released version of Guard. Older
versions may receive fixes when the impact is severe and the patch can be
backported safely.

## Reporting a Vulnerability

Please report security issues privately. Use GitHub private vulnerability
reporting for `MauroProto/guard` when it is available. If private reporting is
not available, contact the maintainer through a private channel before opening a
public issue with exploit details.

Useful reports include:

- bypasses in dependency, workflow, policy, or agent-tooling checks;
- installer, checksum, release, or update verification failures;
- false negatives that allow malicious dependency or workflow changes through;
- plugin behavior that blocks normal development commands unexpectedly;
- cases where Guard reports a clean result even though part of the scan failed.

## Disclosure Process

The maintainer will acknowledge valid reports, investigate impact, prepare a
fix, and publish release notes once users have a safe upgrade path. Please avoid
public proof-of-concept details until a fix is released.

## Scope

In scope:

- Guard CLI and policy behavior;
- Claude Code plugin hooks and bundled scripts;
- release artifacts, checksums, and installer behavior;
- GitHub Actions workflows shipped in this repository.

Out of scope:

- vulnerabilities in third-party package registries or GitHub Actions services;
- findings that require unrelated local machine compromise before Guard runs;
- low-confidence false positives without a realistic bypass or denial-of-service
  path.
