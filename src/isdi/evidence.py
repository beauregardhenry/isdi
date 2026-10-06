"""Evidence copies of scans, and signed exports.

By default the raw dump of a phone is deleted when its scan ends
(DATA_PROTECTION.md). When the operator asks for an evidence copy, the dump
is kept instead, encrypted, with its SHA-256 recorded in the database and
the audit log at the moment of the scan.

`export_package` writes everything about one scan to a directory:

- the dump, as ISDi wrote it (for Android, account email addresses are
  redacted and whitespace normalised, unless an unredacted copy was asked
  for, which is the adb output as received; for iOS, as pymobiledevice3
  wrote it);
- results.json: the scan record and its apps, decrypted;
- audit.json: the audit entries for the scan, and the log's newest entry;
- manifest.json: what the package is, how it was made, and the SHA-256 of
  each file;
- manifest.sig: an Ed25519 signature of manifest.json with this
  installation's signing key.

`verify` checks a package (or a single signed export file) without the
passphrase: the signature, and every file against its hash.
"""

import base64
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from isdi import audit, crypto

SIGNATURE_SUFFIX = ".sig"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def preserve(
    scanner, serial: str, scanid: int, clientid: str, unredacted: bool = False
) -> Optional[str]:
    """Keep the dump of the scan that just ran, encrypted. Returns its
    SHA-256, or None if there is no dump (the test scanner has none).

    With unredacted (Android), the copy kept is the adb output as received,
    account email addresses included, instead of the processed dump."""
    from isdi.scanner import raw_path
    from isdi.scanner.db import get_db

    path = scanner.dump_path(serial)
    name = os.path.basename(path).split("_", 1)[1]
    if unredacted:
        path = raw_path(path)
        name = name.replace(".", "-unredacted.", 1)
    if not os.path.exists(path):
        audit.record("evidence_unavailable", clientid=clientid, scanid=scanid)
        return None
    with open(path, "rb") as f:
        raw = f.read()
    digest = _sha256(raw)
    db = get_db()
    db.execute(
        "INSERT INTO evidence (scanid, clientid, created, dump_name, dump_sha256, "
        "size, data, unredacted) VALUES (?,?,?,?,?,?,?,?)",
        (
            scanid,
            clientid,
            _now(),
            crypto.encrypt("dump_name", name),
            digest,
            len(raw),
            crypto.encrypt("data", base64.b64encode(raw).decode("ascii")),
            int(unredacted),
        ),
    )
    db.commit()
    audit.record(
        "evidence_preserved",
        clientid=clientid,
        scanid=scanid,
        details={"dump_sha256": digest, "size": len(raw), "unredacted": unredacted},
    )
    return digest


def evidence_for_scan(scanid: int) -> Optional[dict]:
    from isdi.scanner.db import query_db

    return query_db("SELECT * FROM evidence WHERE scanid=?", (scanid,), one=True)


def list_evidence(clientid: Optional[str] = None) -> list:
    from isdi.scanner.db import query_db

    cols = "id, scanid, clientid, created, dump_sha256, size, unredacted"
    if clientid:
        return query_db(
            f"SELECT {cols} FROM evidence WHERE clientid=? ORDER BY id", (clientid,)
        )
    return query_db(f"SELECT {cols} FROM evidence ORDER BY id")


def _signature_record(data: bytes, public: bytes) -> dict:
    return {
        "algorithm": "Ed25519",
        "public_key": base64.b64encode(public).decode("ascii"),
        "fingerprint": crypto.fingerprint(public),
        "signature": base64.b64encode(crypto.sign(data)).decode("ascii"),
    }


def _write(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def sign_file(path, public: bytes) -> Path:
    """Write path + ".sig": a signature of the file's exact bytes."""
    path = Path(path)
    sig = Path(str(path) + SIGNATURE_SUFFIX)
    record = _signature_record(path.read_bytes(), public)
    _write(sig, json.dumps(record, indent=2).encode() + b"\n")
    return sig


def export_package(scanid: int, outdir, public: bytes) -> Path:
    """Write the evidence package for one scan to outdir (created, and
    readable only by the owner). The package is not encrypted."""
    from isdi import __version__
    from isdi.scanner import blocklist
    from isdi.scanner.db import get_app_info_from_db, get_scan_res_from_db

    scan = get_scan_res_from_db(scanid)
    if not scan:
        raise LookupError(f"no scan {scanid}")
    ev = evidence_for_scan(scanid)
    outdir = Path(outdir)
    outdir.mkdir(mode=0o700, parents=True, exist_ok=False)

    files = {}

    def add(name: str, data: bytes) -> None:
        _write(outdir / name, data)
        files[name] = {"sha256": _sha256(data), "size": len(data)}

    if ev:
        raw = base64.b64decode(ev["data"])
        if _sha256(raw) != ev["dump_sha256"]:
            raise ValueError("the stored dump does not match its recorded hash")
        add(f"scan-{scanid}-{ev['dump_name']}", raw)
    results = {"scan": scan, "apps": get_app_info_from_db(scanid)}
    add("results.json", json.dumps(results, indent=2, default=str).encode() + b"\n")
    trail = {
        "entries": [
            e for e in audit.entries(scan["clientid"]) if e["scanid"] == scanid
        ],
        "audit_log_newest_entry": audit.head(),
    }
    add("audit.json", json.dumps(trail, indent=2, default=str).encode() + b"\n")

    manifest = {
        "format": "isdi-evidence-package/1",
        "made_by": f"ISDi {__version__} (https://github.com/beauregardhenry/isdi)",
        "exported_at": _now(),
        "exported_by": audit.operator(),
        "scan": {
            "id": scanid,
            "clientid": scan["clientid"],
            "time": scan["time"],
            "operator": scan.get("operator"),
            "device": scan["device"],
            "device_model": scan.get("device_model"),
            "device_serial_hmac": scan["serial"],
        },
        "raw_dump": (
            {
                "kept_at": ev["created"],
                "sha256_recorded_at_scan": ev["dump_sha256"],
                "unredacted": bool(ev["unredacted"]),
                "note": (
                    "The phone's output as ISDi received it from adb during the "
                    "scan, as UTF-8 text, unredacted. Not a forensic image."
                    if ev["unredacted"]
                    else "As written by ISDi during the scan. Android dumps "
                    "have account email addresses redacted and whitespace "
                    "normalised; they are not a forensic image of the phone."
                ),
            }
            if ev
            else None
        ),
        "blocklist_sha256": blocklist.BLOCKLIST_SHA256,
        "blocklist_updated": blocklist.blocklist_status()["updated"],
        "files": files,
    }
    manifest_bytes = json.dumps(manifest, indent=2, default=str).encode() + b"\n"
    _write(outdir / "manifest.json", manifest_bytes)
    sig = _signature_record(manifest_bytes, public)
    _write(outdir / "manifest.sig", json.dumps(sig, indent=2).encode() + b"\n")
    audit.record(
        "evidence_exported",
        clientid=scan["clientid"],
        scanid=scanid,
        details={"manifest_sha256": _sha256(manifest_bytes), "files": sorted(files)},
    )
    return outdir


def _check_signature(data: bytes, sig_path: Path) -> dict:
    record = json.loads(sig_path.read_text())
    public = base64.b64decode(record["public_key"])
    ok = record.get("algorithm") == "Ed25519" and crypto.verify_signature(
        public, data, base64.b64decode(record["signature"])
    )
    return {"signature_ok": ok, "fingerprint": crypto.fingerprint(public)}


def verify(path) -> dict:
    """Check an evidence package directory, or a file with its .sig.
    Returns {"ok", "fingerprint", "problems"}; no passphrase needed.

    A valid signature shows the files were not changed since they were
    signed with the key whose fingerprint is reported. Compare it with the
    fingerprint the clinic published (`isdi signing-key`)."""
    path = Path(path)
    problems = []
    if path.is_dir():
        manifest_bytes = (path / "manifest.json").read_bytes()
        result = _check_signature(manifest_bytes, path / "manifest.sig")
        if not result["signature_ok"]:
            problems.append("manifest.json does not match its signature")
        manifest = json.loads(manifest_bytes)
        for name, info in manifest["files"].items():
            f = path / name
            if not f.is_file():
                problems.append(f"{name} is missing")
            elif _sha256(f.read_bytes()) != info["sha256"]:
                problems.append(f"{name} was changed")
        listed = set(manifest["files"]) | {"manifest.json", "manifest.sig"}
        for extra in sorted(p.name for p in path.iterdir() if p.name not in listed):
            problems.append(f"{extra} is not part of the package")
    else:
        result = _check_signature(path.read_bytes(), Path(str(path) + SIGNATURE_SUFFIX))
        if not result["signature_ok"]:
            problems.append(f"{path.name} does not match its signature")
    return {
        "ok": not problems,
        "fingerprint": result["fingerprint"],
        "problems": problems,
    }
