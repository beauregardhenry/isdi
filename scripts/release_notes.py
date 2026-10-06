#!/usr/bin/env python3
"""Print the CHANGELOG.md section for a version: the top of its release
notes. Exits 1 if there is none.

    python scripts/release_notes.py 1.6.0

With --unreleased, print the CHANGELOG.md versions newer than the given
one (changes on main not yet released) and exit 1 if there are any: a
blocklist-only patch release must not ship them unannounced.

    python scripts/release_notes.py --unreleased 1.7.1
"""

import re
import sys
from pathlib import Path


def section(text: str, version: str):
    """The body of the "## <version>" section, or None."""
    match = re.search(
        rf"^## {re.escape(version)}[ \t]*\n(.*?)(?=^## |\Z)", text, re.M | re.S
    )
    if not match or not match.group(1).strip():
        return None
    return "## What changes for staff\n\n" + match.group(1).strip() + "\n"


def _key(version: str):
    return tuple(int(part) for part in version.split("."))


def newer_sections(text: str, version: str) -> list:
    """The "## X.Y.Z" versions in the changelog newer than `version`."""
    found = re.findall(r"^## (\d+(?:\.\d+)+)[ \t]*$", text, re.M)
    return [v for v in found if _key(v) > _key(version)]


def main(argv) -> int:
    if argv[1] == "--unreleased":
        changelog = Path(argv[3] if len(argv) > 3 else "CHANGELOG.md")
        newer = newer_sections(changelog.read_text(encoding="utf-8"), argv[2])
        for v in newer:
            print(v)
        return 1 if newer else 0
    version = argv[1]
    changelog = Path(argv[2] if len(argv) > 2 else "CHANGELOG.md")
    notes = section(changelog.read_text(encoding="utf-8"), version)
    if notes is None:
        print(f"CHANGELOG.md has no section for {version}", file=sys.stderr)
        return 1
    sys.stdout.write(notes)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
