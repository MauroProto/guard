#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALLER="$REPO_ROOT/install.sh"

python3 - "$INSTALLER" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")

requirements = {
    "insecure override": "GUARD_INSTALL_INSECURE",
    "checksum cleanup trap": "trap 'rm -f \"$TMP\" \"$CHECKSUM_TMP\"' EXIT",
    "missing checksum failure": "Checksum file is required",
    "missing checksum entry failure": "No checksum entry found",
    "missing sha256 tool failure": "No SHA-256 checksum tool found",
}

missing = [name for name, needle in requirements.items() if needle not in text]
if missing:
    raise SystemExit("install.sh is missing hardening checks: " + ", ".join(missing))

for forbidden in (
    'curl -fsSL "$CHECKSUM_URL" -o "$CHECKSUM_TMP" 2>/dev/null || true',
    'wget -q "$CHECKSUM_URL" -O "$CHECKSUM_TMP" 2>/dev/null || true',
):
    if forbidden in text:
        raise SystemExit("install.sh still allows checksum download failures silently")

print("install hardening OK")
PY
