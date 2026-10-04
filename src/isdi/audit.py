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

Anchors close both gaps when kept outside the clinic's control: `isdi
audit anchor` writes a small signed statement of the newest entry (its id,
time and MAC; no client data), to send to someone else, such as counsel.
`isdi audit verify --anchor FILE` then checks that the log still contains
that entry unchanged, so a log rebuilt or cut short after the anchor was
sent no longer matches it.

Details (old and new values of an edit, app ids, ...) are client data:
they are encrypted, and erasing a client blanks them. The entry itself, and
a MAC of its details, remain, so the chain still verifies and shows that
something was erased, and when.
"""

import contextlib
import hashlib
import hmac
import json
import threading
from datetime import datetime, timezone
from typing import Any, Optional

from isdi import crypto

GENESIS = "0" * 64
_lock = threading.Lock()

# Who is acting, in order:
# - in the web interface, the signed-in user (isdi/users.py), set per
#   request, and carried into background scans with acting_as();
# - on the command line, the name given with --operator (or asked for):
#   the operator's own statement, since commands need the passphrase but
#   no account.
_operator: Optional[str] = None
_acting = threading.local()


def set_operator(name: Optional[str]) -> None:
    global _operator
    _operator = (name or "").strip() or None


@contextlib.contextmanager
def acting_as(name: Optional[str]):
    """Record entries made in this thread under name."""
    saved = getattr(_acting, "name", _UNSET)
    _acting.name = name
    try:
        yield
    finally:
        if saved is _UNSET:
            del _acting.name
        else:
            _acting.name = saved


_UNSET = object()


def operator() -> Optional[str]:
    name = getattr(_acting, "name", _UNSET)
    if name is not _UNSET:
        return name
    try:
        from flask import g, has_request_context

        if has_request_context() and "operator" in g:
            return g.operator
    except ImportError:  # pragma: no cover
        pass
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
    conn=None,
) -> int:
    """Append an entry; returns its id. conn: a database other than the
    app's (with the dict row factory), e.g. one just restored."""
    from isdi.scanner.db import get_db

    # Stored as JSON: MAC the same form that will be read back.
    details = json.loads(json.dumps(details, default=str))
    db = conn or get_db()
    with _lock:
        last = db.execute("SELECT id, mac FROM audit_log ORDER BY id DESC LIMIT 1")
        last = last.fetchone()
        row = {
            "id": (last["id"] + 1) if last else 1,
            "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "operator": operator(),
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


ANCHOR_FORMAT = "isdi-audit-anchor/1"


def last_action(action: str) -> Optional[dict]:
    """The newest entry for an action (id and time), or None."""
    from isdi.scanner.db import query_db

    return query_db(
        "SELECT id, time FROM audit_log WHERE action=? ORDER BY id DESC LIMIT 1",
        (action,),
        one=True,
    )


def last_anchor() -> Optional[dict]:
    """The newest anchor made, as recorded in the log (id and time)."""
    return last_action("audit_anchored")


def make_anchor() -> dict:
    """Record that an anchor is being made, then describe the newest entry
    (that record). Holds no client data: ids, times and MACs only."""
    from isdi import __version__
    from isdi.scanner.db import query_db

    record("audit_anchored")
    newest = query_db(
        "SELECT id, time, mac FROM audit_log ORDER BY id DESC LIMIT 1", one=True
    )
    return {
        "format": ANCHOR_FORMAT,
        "made_by": f"ISDi {__version__} (https://github.com/beauregardhenry/isdi)",
        "made_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "entries": newest["id"],
        "newest_entry": dict(newest),
    }


def check_anchor(anchor: dict) -> Optional[str]:
    """Whether the log still holds the anchored entry, unchanged. Returns
    the problem, or None. Run verify() too: an anchor covers the chain up
    to its entry only if the chain itself verifies."""
    from isdi.scanner.db import query_db

    if anchor.get("format") != ANCHOR_FORMAT:
        return "not an ISDi audit anchor"
    want = anchor["newest_entry"]
    row = query_db(
        "SELECT id, time, mac FROM audit_log WHERE id=?", (want["id"],), one=True
    )
    if row is None:
        return f"entry {want['id']} is no longer in the log"
    if row["mac"] != want["mac"] or row["time"] != want["time"]:
        return f"entry {want['id']} is not the one anchored: the log was rewritten"
    return None


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
