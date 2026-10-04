"""Removing client data that must not stay on disk unencrypted.

ISDi keeps client data only in the database, encrypted (isdi/crypto.py).
Raw phone dumps exist only while a phone is being scanned. Older versions
also left plaintext copies behind: raw dumps, CSV reports and the
pseudonymisation key. Those are deleted at every start.

Deleting a file does not reliably erase it from an SSD or a journaling file
system; full-disk encryption (FileVault, BitLocker, LUKS) is what protects
anything a file system leaves behind. See DATA_PROTECTION.md.
"""

import logging
import os
from pathlib import Path


def purge_plaintext_files(config) -> dict:
    """Delete raw dumps, old plaintext reports, and the old plaintext
    pseudonymisation key once the keyfile holds it. Returns counts."""
    from isdi.scanner import purge_raw_dumps

    removed = {"dumps": purge_raw_dumps(), "reports": 0, "legacy_pii_key": 0}
    for legacy in getattr(config, "legacy_dumps_dirs", []):
        for dump in Path(legacy).glob("*"):
            if dump.is_file():
                dump.unlink()
                removed["dumps"] += 1
    for report in Path(config.reports_dir).glob("*.csv"):
        report.unlink()
        removed["reports"] += 1
    if Path(config.keyfile).exists() and Path(config.legacy_pii_key_file).exists():
        os.remove(config.legacy_pii_key_file)
        removed["legacy_pii_key"] = 1
    if any(removed.values()):
        logging.info("Removed plaintext files: %s", removed)
    return removed


def read_legacy_pii_key(config):
    """The pseudonymisation key from before encryption at rest, if any, so
    the keyfile can keep it (stored serial pseudonyms then still match)."""
    path = Path(config.legacy_pii_key_file)
    return path.read_bytes()[:32] if path.exists() else None
