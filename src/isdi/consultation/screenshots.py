"""Screenshots kept with a consultation record, as evidence of what was on
the client's phone or account.

Each one belongs to a client and a part of the record (target): a device
("device:<key>"), an app on it ("app:<key>:<app>") or a section of an
account check ("account:<id>:<section>"). The image is stored in the
database, encrypted, with its SHA-256 at the time it was taken. Nothing is
written to disk, and screenshots go with the client's other records when
they are exported or erased.

Sherloc wrote PNG files to a folder served by the web app, named after the
device's serial number.
"""

import base64
import hashlib
import re
from datetime import datetime, timezone
from subprocess import PIPE, CalledProcessError, TimeoutExpired, run
from typing import List, Optional

from isdi import crypto
from isdi.config import get_config
from isdi.scanner.db import get_db, query_db

PNG = b"\x89PNG\r\n\x1a\n"
JPEG = b"\xff\xd8\xff"
MAX_BYTES = 15 * 1024 * 1024

_TARGET = re.compile(
    r"device:(scan-\d+|manual-\d+)"
    r"|app:(scan-\d+|manual-\d+):[^\n]{1,300}"
    r"|account:\d+:(suspicious_logins|recovery_settings|two_factor_settings|security_questions)"
)


class ScreenshotError(Exception):
    """Shown to staff as it is."""


def valid_target(target: str) -> bool:
    return isinstance(target, str) and _TARGET.fullmatch(target) is not None


def image_type(data: bytes) -> Optional[str]:
    if data.startswith(PNG):
        return "image/png"
    if data.startswith(JPEG):
        return "image/jpeg"
    return None


def capture_android(serial: str) -> bytes:
    """What is on the phone's screen now, as PNG bytes."""
    argv = [get_config().ADB_PATH, "-s", serial, "exec-out", "screencap", "-p"]
    try:
        result = run(argv, check=True, stdout=PIPE, stderr=PIPE, timeout=30)
    except CalledProcessError:
        raise ScreenshotError(
            "The phone did not take the screenshot. Is it still connected?"
        )
    except (OSError, TimeoutExpired):
        raise ScreenshotError("Could not reach the phone with adb.")
    if not result.stdout.startswith(PNG):
        raise ScreenshotError(
            "The phone did not return an image. Is the screen unlocked?"
        )
    return result.stdout


def save(clientid: str, target: str, data: bytes, source: str) -> int:
    if not valid_target(target):
        raise ValueError("unknown screenshot target")
    if len(data) > MAX_BYTES:
        raise ScreenshotError("The image is larger than 15 MB.")
    mime = image_type(data)
    if mime is None:
        raise ScreenshotError("Only PNG and JPEG images can be kept.")
    db = get_db()
    cur = db.execute(
        "INSERT INTO screenshots (clientid, created, target, source, mime, sha256, data) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            clientid,
            datetime.now(timezone.utc).isoformat(timespec="seconds"),
            crypto.encrypt("target", target),
            source,
            mime,
            hashlib.sha256(data).hexdigest(),
            crypto.encrypt("data", base64.b64encode(data).decode("ascii")),
        ),
    )
    db.commit()
    return cur.lastrowid or 0


def listing(clientid: str, target: Optional[str] = None) -> List[dict]:
    """The client's screenshots (without the images), oldest first."""
    rows = query_db(
        "SELECT id, created, target, source, mime, sha256 FROM screenshots "
        "WHERE clientid=? ORDER BY id",
        (clientid,),
    )
    return [r for r in rows if target is None or r["target"] == target]


def image(clientid: str, shot_id: int) -> Optional[dict]:
    row = query_db(
        "SELECT id, mime, data, target FROM screenshots WHERE clientid=? AND id=?",
        (clientid, shot_id),
        one=True,
    )
    if not row:
        return None
    row["bytes"] = base64.b64decode(row.pop("data"))
    return row


def data_uri(clientid: str, shot_id: int) -> str:
    """For the report, which is rendered without the web app."""
    shot = image(clientid, shot_id)
    if not shot:
        return ""
    return f"data:{shot['mime']};base64," + base64.b64encode(shot["bytes"]).decode()


def delete(clientid: str, shot_id: int) -> bool:
    db = get_db()
    n = db.execute(
        "DELETE FROM screenshots WHERE clientid=? AND id=?", (clientid, shot_id)
    ).rowcount
    db.commit()
    return n > 0


def by_target(clientid: str) -> dict:
    """target -> its screenshots, for pages that show several parts."""
    out: dict = {}
    for row in listing(clientid):
        out.setdefault(row["target"], []).append(row)
    return out
