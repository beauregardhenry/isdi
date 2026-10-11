"""Where a client's consultation answers are kept.

One row per client and kind in `consultation_docs`, the whole document in
one encrypted column (isdi/crypto.py), next to the client's scans and notes.
Sherloc kept one set of answers for the whole computer and deleted them at
the end of each consultation; here each client has their own, and they are
exported and erased with the client's other records (scanner/db.py).
"""

from datetime import datetime, timezone
from typing import Any

from isdi.scanner.db import get_db, query_db
from isdi import crypto

#: What can be stored, and what an empty one looks like.
KINDS = {
    "taq": dict,
    "accounts": list,
    "devices": list,
    "notes": dict,
    # The client's name as it should appear on the full report.
    "report_name": str,
}


def _check(kind: str) -> None:
    if kind not in KINDS:
        raise ValueError(f"unknown consultation document {kind!r}")


def load(clientid: str, kind: str) -> Any:
    """The stored document, or an empty one."""
    _check(kind)
    row = query_db(
        "SELECT doc FROM consultation_docs WHERE clientid=? AND kind=?",
        (clientid, kind),
        one=True,
    )
    if not row or row["doc"] is None:
        return KINDS[kind]()
    return row["doc"]


def save(clientid: str, kind: str, doc: Any) -> None:
    """Replace the stored document."""
    _check(kind)
    if not isinstance(doc, KINDS[kind]):
        raise TypeError(f"{kind} must be a {KINDS[kind].__name__}")
    db = get_db()
    db.execute(
        "INSERT INTO consultation_docs (clientid, kind, doc, updated) VALUES (?, ?, ?, ?) "
        "ON CONFLICT(clientid, kind) DO UPDATE SET doc=excluded.doc, updated=excluded.updated",
        (
            clientid,
            kind,
            crypto.encrypt("doc", doc),
            datetime.now(timezone.utc).isoformat(timespec="seconds"),
        ),
    )
    db.commit()


def load_all(clientid: str) -> dict:
    """Every kind, for the overview and the report."""
    return {kind: load(clientid, kind) for kind in KINDS}


def delete(clientid: str, kind: str) -> None:
    _check(kind)
    db = get_db()
    db.execute(
        "DELETE FROM consultation_docs WHERE clientid=? AND kind=?", (clientid, kind)
    )
    db.commit()
