"""Append-only audit log: who did what, and when.

Every scan, note, edit, uninstall, export and erasure adds an entry to the
audit_log table. Entries form a chain: each one's MAC (HMAC-SHA256 with a
key derived from the data key) covers its own fields and the previous
entry's MAC. Changing, inserting or removing an entry in the middle breaks
the chain, and `isdi audit verify` reports where; without the passphrase an
entry cannot be forged.

Two limits, stated in DATA_PROTECTION.md and COURT_RECORDS.md:
- Someone with the passphrase could rebuild the whole chain. Exports record
  the newest entry (its id and MAC), so a chain rebuilt later no longer
  matches an export made earlier.
- Removing the newest entries leaves a shorter chain that still verifies;
  again, an earlier export shows that entries are missing.

Details (old and new values of an edit, app ids, ...) are client data:
they are encrypted, and erasing a client blanks them. The entry itself, and
a MAC of its details, remain, so the chain still verifies and shows that
something was erased, and when.
"""

import hashlib
import hmac
import json
import threading
from datetime import datetime, timezone
from typing import Any, Optional

from isdi import crypto

GENESIS = "0" * 64
_lock = threading.Lock()

# The person running ISDi, as given at startup (see `isdi run --operator`).
# ISDi has no user accounts, so this is what the operator says, not proof.
_operator: Optional[str] = None


def set_operator(name: Optional[str]) -> None:
    global _operator
    _operator = (name or "").strip() or None


def operator() -> Optional[str]:
    return _operator


def _key() -> bytes:
    return crypto.derived_key("audit")


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode(
        "utf-8"
    )


def _mac(data: Any) -> str:
    return hmac.new(_key(), _canonical(data), hashlib.sha256).hexdigest()


def _entry_mac(row: dict) -> str:
    return _mac(
        [
            row["id"],
            row["time"],
            row["operator"],
            row["action"],
            row["clientid"],
            row["scanid"],
            row["details_mac"],
            row["prev"],
        ]
    )


def record(
    action: str,
    clientid: Optional[str] = None,
    scanid: Optional[int] = None,
    details: Optional[dict] = None,
) -> int:
    """Append an entry; returns its id."""
    from isdi.scanner.db import get_db

    # Stored as JSON: MAC the same form that will be read back.
    details = json.loads(json.dumps(details, default=str))
    db = get_db()
    with _lock:
        last = db.execute("SELECT id, mac FROM audit_log ORDER BY id DESC LIMIT 1")
        last = last.fetchone()
        row = {
            "id": (last["id"] + 1) if last else 1,
            "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "operator": _operator,
            "action": action,
            "clientid": clientid,
            "scanid": scanid,
            "details_mac": _mac(details),
            "prev": last["mac"] if last else GENESIS,
        }
        row["mac"] = _entry_mac(row)
        db.execute(
            "INSERT INTO audit_log (id, time, operator, action, clientid, scanid, "
            "details, details_mac, prev, mac) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                row["id"],
                row["time"],
                crypto.encrypt("operator", row["operator"]),
                action,
                clientid,
                scanid,
                crypto.encrypt("details", details),
                row["details_mac"],
                row["prev"],
                row["mac"],
            ),
        )
        db.commit()
    return row["id"]


def entries(clientid: Optional[str] = None) -> list:
    from isdi.scanner.db import query_db

    if clientid is None:
        return query_db("SELECT * FROM audit_log ORDER BY id")
    return query_db(
        "SELECT * FROM audit_log WHERE clientid=? ORDER BY id", args=(clientid,)
    )


def head() -> Optional[dict]:
    """The newest entry's id and MAC: recorded in exports to pin history."""
    from isdi.scanner.db import query_db

    row = query_db("SELECT id, mac FROM audit_log ORDER BY id DESC LIMIT 1", one=True)
    return {"id": row["id"], "mac": row["mac"]} if row else None


def verify() -> dict:
    """Check the whole chain. Returns {"ok", "entries", "erased", "problem"}."""
    rows = entries()
    prev, erased = GENESIS, 0
    for expected_id, row in enumerate(rows, start=1):
        problem = None
        if row["id"] != expected_id:
            problem = f"entry {expected_id} is missing"
        elif row["prev"] != prev:
            problem = f"entry {row['id']} does not follow entry {row['id'] - 1}"
        elif _entry_mac(row) != row["mac"]:
            problem = f"entry {row['id']} was altered"
        elif row["details"] is None:
            erased += 1
        elif _mac(row["details"]) != row["details_mac"]:
            problem = f"the details of entry {row['id']} were altered"
        if problem:
            return {
                "ok": False,
                "entries": len(rows),
                "erased": erased,
                "problem": problem,
            }
        prev = row["mac"]
    return {"ok": True, "entries": len(rows), "erased": erased, "problem": None}


def erase_client_details(clientid: str) -> int:
    """Blank the details of a client's entries (their data is being erased);
    the entries and the chain remain."""
    from isdi.scanner.db import get_db

    db = get_db()
    n = db.execute(
        "UPDATE audit_log SET details=NULL WHERE clientid=? AND details IS NOT NULL",
        (clientid,),
    ).rowcount
    db.commit()
    return n


def erase_scan_details(scanids) -> int:
    """Blank the details of entries about these scans (deleted with their
    device's data)."""
    from isdi.scanner.db import get_db

    db = get_db()
    n = 0
    for scanid in scanids:
        n += db.execute(
            "UPDATE audit_log SET details=NULL WHERE scanid=? AND details IS NOT NULL",
            (scanid,),
        ).rowcount
    db.commit()
    return n


def changes(before: dict, after: dict) -> dict:
    """field -> [old, new] for the fields that differ."""
    return {
        k: [before.get(k), after.get(k)]
        for k in sorted(set(before) | set(after))
        if before.get(k) != after.get(k)
    }
