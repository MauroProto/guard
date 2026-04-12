# 🛡 Guard

**Supply chain security CLI for pnpm projects.**

Guard scans your JavaScript/TypeScript repositories for supply chain risks, enforces security policies, and auto-fixes issues — all from the terminal.

<p align="center">
  <img src="https://img.shields.io/badge/go-%3E%3D1.23-blue" alt="Go 1.23+">
  <img src="https://img.shields.io/badge/pnpm-supported-orange" alt="pnpm">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="MIT License">
</p>

---

## Install

### One-liner (macOS/Linux)

```bash
curl -fsSL https://raw.githubusercontent.com/MauroProto/guard/main/install.sh | sh
```

### With Go

```bash
go install github.com/MauroProto/guard/cmd/guard@latest
```

### From source

```bash
git clone https://github.com/MauroProto/guard.git
cd guard
make install
```

---

## Quick Start

```bash
# Scan your repo
guard scan

# Auto-fix everything
guard fix

# Set up secure baseline from scratch
guard init
```

---

## Commands

| Command | Alias | Description |
|---------|-------|-------------|
| `guard scan` | `guard s` | Scan the repository for security issues |
| `guard fix` | `guard f` | Auto-fix issues found by scan |
| `guard init` | `guard i` | Create a secure baseline (policy, pnpm config, CI workflow) |
| `guard ci` | `guard c` | Strict scan mode for CI pipelines |
| `guard diff` | `guard d` | Compare two local package versions for risk signals |
| `guard approve` | `guard ab` | Approve a package that needs build scripts |

### Typical workflow

```bash
guard scan       # 1. See what's wrong
guard fix        # 2. Fix everything
guard scan       # 3. Verify it's clean
```

---

## What it checks

### Repository structure
- Missing `pnpm-lock.yaml`
- Missing `packageManager` field in `package.json`
- Missing `engines.node` declaration

### pnpm security settings
- `minimumReleaseAge` not configured or too low
- `blockExoticSubdeps` disabled
- `strictDepBuilds` disabled
- `trustPolicy` not set to `no-downgrade`
- Unapproved build scripts in `allowBuilds`

### GitHub workflow hygiene
- Actions not pinned to full commit SHA
- Missing or overly broad `permissions` block
- Missing `CODEOWNERS` for workflow protection

### Package diff heuristics (`guard diff`)

> **Note:** `guard diff` currently works with local directories only (`--from-dir`/`--to-dir`). Registry download is planned for a future release.

```bash
guard diff lodash@4.17.20..4.17.21 --from-dir old/ --to-dir new/
```

Detects:
- New install scripts (postinstall, preinstall)
- Remote fetch / command execution patterns
- New binary files
- Obfuscation signals (eval, long hex strings)
- Sensitive path access (.env, .ssh, .npmrc)

---

## Output formats

```bash
guard scan                         # Terminal with colors (default)
guard scan --format json           # JSON for automation
guard scan --format sarif          # SARIF 2.1.0 for GitHub Code Scanning
guard scan --format markdown       # Markdown table for PR comments
```

---

## Language

Guard auto-detects your system language.

```bash
guard --lang en scan    # Force English
guard --lang es scan    # Force Spanish
```

---

## Presets

```bash
guard init --preset strict      # 72h release age, blocks medium+
guard init --preset balanced    # 24h release age, blocks high+ (default)
guard init --preset local       # 1h release age, blocks critical only
```

---

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | No blocking findings |
| `1` | Blocking findings detected |
| `2` | Usage error |

---

## CI Integration

Add to `.github/workflows/guard.yml`:

```yaml
name: Guard
on: [pull_request]
permissions:
  contents: read
jobs:
  guard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<SHA>
      - uses: actions/setup-go@<SHA>
        with:
          go-version: '1.23'
      - run: go install github.com/MauroProto/guard/cmd/guard@latest
      - run: guard ci --format sarif --output guard.sarif
      - uses: github/codeql-action/upload-sarif@<SHA>
        if: always()
        with:
          sarif_file: guard.sarif
```

---

## Development

```bash
git clone https://github.com/MauroProto/guard.git
cd guard
make build       # Build binary
make test        # Run tests
make install     # Install to GOPATH/bin
```

---

## License

MIT
