"""Which client records the signed-in user may open.

- Scans are opened and changed only in the session of their client: the
  client the user is working with now (session["clientid"]).
- Consultation notes of other clients are listed and edited only by
  supervisors, or by the staff account that started that client
  (isdi/users.py).

Refusals are recorded in the audit log.
"""

from flask import g, session

from isdi import audit, users
from isdi.scanner import db


def session_scan(scanid: int):
    """The scan, if it belongs to the session's client; else None."""
    scan = db.get_scan_res_from_db(scanid)
    if scan and scan.get("clientid") == session.get("clientid"):
        return scan
    if scan:
        refused(scan.get("clientid"), scanid=scanid)
    return None


def can_open(clientid: str) -> bool:
    return "user" in g and users.can_open(g.user, clientid)


def refused(clientid, scanid=None) -> None:
    from flask import request

    audit.record(
        "access_refused",
        clientid=clientid,
        scanid=scanid,
        details={"path": request.path},
    )
