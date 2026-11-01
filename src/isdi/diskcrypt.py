"""Whether the disk holding isdi's data is encrypted.

DATA_PROTECTION.md asks for full-disk encryption: on an SSD a deleted dump
can outlive its deletion, and a lost laptop holds everything the file
system left behind. At start, isdi warns when it can tell encryption is
off. When it cannot tell, it says nothing: a false alarm teaches people to
ignore the warning.

- macOS: `fdesetup status` ("FileVault is On." / "FileVault is Off.";
  exit status 2 means on but busy). Any other answer is unknown.
- Linux: the block device under isdi's data folder is followed through
  /sys (device-mapper layers via `slaves/`) looking for a dm-crypt layer,
  whose dm uuid starts with "CRYPT-" (LUKS). An ecryptfs mount over the
  folder also counts. A file system with no block device in /sys (btrfs
  subvolumes, ZFS, overlay) is unknown. So is WSL: its Linux disk is a
  file on Windows, and BitLocker cannot be seen from inside.
- Termux, Windows and anything else: unknown.
"""

import os
import platform
import re
import subprocess
from pathlib import Path
from typing import Optional, Set, Tuple

FDESETUP = "fdesetup"
SYS = Path("/sys")
MOUNTS = Path("/proc/mounts")
_FILEVAULT_RE = re.compile(r"FileVault is (On|Off)\b")


def status(
    path, system: Optional[str] = None, dev: Optional[Tuple[int, int]] = None
) -> str:
    """ "on", "off" or "unknown" for the disk holding `path`."""
    if os.environ.get("PREFIX"):
        return "unknown"  # Termux
    system = system or platform.system()
    try:
        if system == "Darwin":
            return _macos()
        if system == "Linux" and not _is_wsl():
            return _linux(Path(path), dev)
    except (OSError, subprocess.SubprocessError, ValueError):
        pass
    return "unknown"


def warning(state: str, system: Optional[str] = None) -> Optional[str]:
    """The message to show at start, or None."""
    if state != "off":
        return None
    system = system or platform.system()
    how = (
        "Turn on FileVault (System Settings > Privacy & Security)"
        if system == "Darwin"
        else "Use full-disk encryption (LUKS)"
    )
    return (
        "This disk does not appear to be encrypted. Raw phone data is written "
        "to it during scans, and a deleted file can survive on an SSD. "
        f"{how}. See DATA_PROTECTION.md."
    )


def _is_wsl() -> bool:
    return "microsoft" in platform.release().lower()


def _macos() -> str:
    p = subprocess.run([FDESETUP, "status"], capture_output=True, text=True, timeout=15)
    m = _FILEVAULT_RE.search(p.stdout)
    if p.returncode not in (0, 2) or not m:
        return "unknown"
    return "on" if m.group(1) == "On" else "off"


def _linux(path: Path, dev: Optional[Tuple[int, int]]) -> str:
    if _ecryptfs_over(path):
        return "on"
    if dev is None:
        st = os.stat(_existing(path))
        dev = (os.major(st.st_dev), os.minor(st.st_dev))
    link = SYS / "dev" / "block" / f"{dev[0]}:{dev[1]}"
    if not link.exists():
        return "unknown"
    found = _crypt_below(link.resolve(), set())
    return {True: "on", False: "off", None: "unknown"}[found]


def _crypt_below(device: Path, seen: Set[Path]) -> Optional[bool]:
    """True if a dm-crypt layer is at or below `device`, False if none is,
    None if /sys does not make sense (a loop)."""
    if device in seen:
        return None
    seen.add(device)
    uuid = device / "dm" / "uuid"
    if uuid.is_file() and uuid.read_text().strip().startswith("CRYPT-"):
        return True
    slaves = device / "slaves"
    below = sorted(slaves.iterdir()) if slaves.is_dir() else []
    result: Optional[bool] = False
    for s in below:
        r = _crypt_below(s.resolve(), seen)
        if r:
            return True
        if r is None:
            result = None
    return result


def _ecryptfs_over(path: Path) -> bool:
    target = str(_existing(path).resolve())
    for line in MOUNTS.read_text().splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[2] == "ecryptfs":
            mount = parts[1].rstrip("/")
            if target == mount or target.startswith(mount + "/"):
                return True
    return False


def _existing(path: Path) -> Path:
    while not path.exists() and path != path.parent:
        path = path.parent
    return path
