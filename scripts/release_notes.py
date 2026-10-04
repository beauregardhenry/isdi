#!/usr/bin/env python3
"""Print the CHANGELOG.md section for a version: the top of its release
notes. Exits 1 if there is none.

    python scripts/release_notes.py 1.6.0
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


def main(argv) -> int:
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
