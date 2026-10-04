#!/usr/bin/env python3
"""Merge `pip freeze` outputs taken on several Python versions into one
constraints file.

    python scripts/merge_constraints.py OUT freeze-3.10.txt freeze-3.11.txt ...

Each input is named freeze-<python version>.txt. A package pinned to the
same version on every Python gets one line; otherwise each Python gets its
own line with a python_version marker, so `pip install -c` picks the
version that was tested on the Python in use.
"""

import re
import sys
from pathlib import Path


def read_freeze(text: str) -> dict:
    pins = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name, sep, version = line.partition("==")
        if not sep:
            raise ValueError(f"not a pinned requirement: {line!r}")
        pins[re.sub(r"[-_.]+", "-", name).lower()] = version
    return pins


def merge(freezes: dict) -> str:
    """freezes: python version -> {package: version}."""
    pythons = sorted(freezes, key=lambda v: tuple(int(p) for p in v.split(".")))
    names = sorted(set().union(*freezes.values()))
    lines = []
    for name in names:
        versions = {py: freezes[py].get(name) for py in pythons}
        if None not in versions.values() and len(set(versions.values())) == 1:
            lines.append(f"{name}=={versions[pythons[0]]}")
            continue
        for py, version in versions.items():
            if version is not None:
                lines.append(f'{name}=={version}; python_version == "{py}"')
    return "\n".join(lines) + "\n"


def main(argv) -> int:
    out, inputs = Path(argv[1]), [Path(p) for p in argv[2:]]
    freezes = {}
    for path in inputs:
        match = re.fullmatch(r"freeze-(\d+\.\d+)\.txt", path.name)
        if not match:
            raise SystemExit(f"{path.name}: expected freeze-<python version>.txt")
        freezes[match.group(1)] = read_freeze(path.read_text())
    header = (
        "# The dependency versions this release was tested with, per Python\n"
        "# version. Install with:  pip install -c constraints.txt <wheel>\n"
    )
    out.write_text(header + merge(freezes))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
