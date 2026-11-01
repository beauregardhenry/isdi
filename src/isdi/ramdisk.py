"""A disk in memory for raw phone data (`isdi run --ram-dumps`).

Raw dumps, unredacted evidence output and copied APKs are the only client
data isdi writes to disk unencrypted, and on an SSD a deleted file can
outlive its deletion (DATA_PROTECTION.md). With --ram-dumps the dump
folder lives in memory and is removed when isdi stops:

- Linux (and WSL): a private folder in /dev/shm, after checking that
  /dev/shm really is a memory file system (tmpfs);
- macOS: `hdiutil attach -nomount ram://<sectors>`, formatted with
  `diskutil erasevolume`, detached on exit.

Anything else (Termux, Windows) is refused: isdi then does not start,
rather than quietly keeping the dumps on disk. A disk left by a crash is
removed at the next start (cleanup_leftovers), with or without the flag.

The system can still write memory to its swap file when memory runs low;
that is up to how the computer is set up.
"""

import os
import platform
import re
import secrets
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

PREFIX = "isdi-dumps-"  # Linux folders in /dev/shm
VOLUME_PREFIX = "ISDiDumps-"  # macOS volume names
MEMORY_FILESYSTEMS = {"tmpfs", "ramfs"}
MAX_SIZE_MB = 64 * 1024

SHM = Path("/dev/shm")
MOUNTS = Path("/proc/mounts")
VOLUMES = Path("/Volumes")
HDIUTIL = "hdiutil"
DISKUTIL = "diskutil"
_DEVICE_RE = re.compile(r"/dev/disk[0-9]+")


class RamDiskError(RuntimeError):
    """No disk in memory could be made here."""


@dataclass
class RamDisk:
    path: Path
    _remove: Callable[[], None]

    def remove(self) -> None:
        """Remove the disk and everything on it. Safe to call twice."""
        self._remove()


def create(size_mb: int = 1024, system: Optional[str] = None) -> RamDisk:
    """A private folder in memory, at least size_mb large where the system
    lets a size be set (macOS; /dev/shm has the system's own limit)."""
    if not isinstance(size_mb, int) or not 1 <= size_mb <= MAX_SIZE_MB:
        raise RamDiskError(f"size must be 1 to {MAX_SIZE_MB} MB, not {size_mb!r}")
    if os.environ.get("PREFIX"):
        raise RamDiskError("a disk in memory is not available on Termux")
    system = system or platform.system()
    if system == "Linux":
        return _linux()
    if system == "Darwin":
        return _macos(size_mb)
    raise RamDiskError(f"a disk in memory is not available on {system}")


def cleanup_leftovers(keep=None, system: Optional[str] = None) -> int:
    """Remove disks an earlier isdi left behind (a crash, a power cut),
    except `keep`. Returns how many were removed."""
    system = system or platform.system()
    keep = Path(keep).resolve() if keep else None
    removed = 0
    if system == "Linux" and SHM.is_dir():
        uid = os.getuid()
        for path in SHM.glob(PREFIX + "*"):
            if path.resolve() == keep or not path.is_dir():
                continue
            if path.stat().st_uid != uid:
                continue
            shutil.rmtree(path, ignore_errors=True)
            removed += 1
    elif system == "Darwin" and VOLUMES.is_dir():
        for volume in VOLUMES.glob(VOLUME_PREFIX + "*"):
            if keep is not None and keep.is_relative_to(volume.resolve()):
                continue
            _run(HDIUTIL, "detach", "-force", str(volume))
            removed += 1
    return removed


def _fs_type(path: Path) -> str:
    """The file system type of the mount that holds `path` (/proc/mounts)."""
    target = str(path.resolve())
    best, kind = "", ""
    for line in MOUNTS.read_text().splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        mount = parts[1].replace("\\040", " ")
        inside = target == mount or target.startswith(mount.rstrip("/") + "/")
        if inside and len(mount) > len(best):
            best, kind = mount, parts[2]
    return kind


def _linux() -> RamDisk:
    if not SHM.is_dir():
        raise RamDiskError("/dev/shm is missing, so there is no memory file system")
    try:
        kind = _fs_type(SHM)
    except OSError as e:
        raise RamDiskError(f"cannot tell what /dev/shm is ({type(e).__name__})")
    if kind not in MEMORY_FILESYSTEMS:
        raise RamDiskError(f"/dev/shm is not in memory here ({kind or 'unknown'})")
    path = Path(tempfile.mkdtemp(prefix=PREFIX, dir=SHM))
    os.chmod(path, 0o700)
    return RamDisk(path, lambda: shutil.rmtree(path, ignore_errors=True))


def _run(*argv: str) -> subprocess.CompletedProcess:
    return subprocess.run(argv, capture_output=True, text=True, timeout=60)


def _macos(size_mb: int) -> RamDisk:
    attach = _run(HDIUTIL, "attach", "-nomount", f"ram://{size_mb * 2048}")
    device = attach.stdout.strip()
    if attach.returncode != 0 or not _DEVICE_RE.fullmatch(device):
        raise RamDiskError("hdiutil could not create a disk in memory")

    def detach() -> None:
        _run(HDIUTIL, "detach", "-force", device)

    name = VOLUME_PREFIX + secrets.token_hex(4)
    try:
        erase = _run(DISKUTIL, "erasevolume", "HFS+", name, device)
        volume = VOLUMES / name
        if erase.returncode != 0 or not volume.is_dir():
            raise RamDiskError("diskutil could not format the disk in memory")
        path = volume / "dumps"
        path.mkdir(mode=0o700)
        os.chmod(path, 0o700)
    except BaseException:
        detach()
        raise
    return RamDisk(path, detach)
