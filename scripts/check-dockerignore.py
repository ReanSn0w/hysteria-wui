#!/usr/bin/env python3
"""Guard sensitive paths against accidental inclusion by Docker's COPY . ."""

from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
patterns = [
    line.strip()
    for line in (ROOT / ".dockerignore").read_text().splitlines()
    if line.strip() and not line.lstrip().startswith("#")
]

required = {
    "/runtime/",
    "/migration-backup-*/",
    "/.env*",
    "/*.env",
    "/*.env.*",
    "!/.env.example",
    "/relay/.env*",
}
missing = required - set(patterns)
if missing:
    raise SystemExit(f"Missing Docker context exclusions: {sorted(missing)}")

# Docker processes negations in order. Keep this guard strict so a later
# exception cannot silently reinclude runtime keys or migration archives.
exceptions = [pattern for pattern in patterns if pattern.startswith("!")]
if exceptions != ["!/.env.example"]:
    raise SystemExit(f"Unexpected Docker context exceptions: {exceptions}")

if patterns.index("!/.env.example") < max(
    patterns.index("/.env*"), patterns.index("/*.env"), patterns.index("/*.env.*")
):
    raise SystemExit(".env.example exception must follow env exclusions")

print("Docker context guard: runtime/, migration-backup-*/, env secrets excluded; root .env.example retained")
