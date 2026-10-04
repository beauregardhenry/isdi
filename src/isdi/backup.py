"""Encrypted backups of everything ISDi keeps.

`isdi backup -o FILE` writes one file that holds:
- the keyfile, as it is on disk: the data key in it is encrypted with the
  passphrase and with the recovery key, so it can travel with the backup;
- a consistent copy of the database, encrypted with AES-256-GCM under a
  key derived from the data key, in chunks: each chunk's number, and
  whether it is the last, are authenticated, so a backup that was cut
  short, reordered or altered is refused.

`isdi restore FILE` needs only that file and the passphrase or the
recovery key that was valid when the backup was made, so it works on a new
computer. The database is fully decrypted and checked before anything on
disk is replaced.

Backups contain the encrypted client data and the encrypted keys, nothing
in the clear except the file's format and the time it was made.
"""

import hashlib
import json
import os
import sqlite3
import struct
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from isdi import crypto

FORMAT = "isdi-backup/1"
MAGIC = b"ISDIBACKUP1\n"
CHUNK = 1 << 20


class BackupError(ValueError):
    pass


def _aad(header_digest: bytes, index: int, last: bool) -> bytes:
    return b"isdi-backup" + header_digest + struct.pack(">Q?", index, last)


def _snapshot(database: Path, workdir: Path) -> bytes:
    """A consistent copy of the database, even while ISDi is running."""
    fd, tmp = tempfile.mkstemp(dir=workdir, prefix=".backup-", suffix=".db")
    os.close(fd)
    try:
        src = sqlite3.connect(database)
        dst = sqlite3.connect(tmp)
        with dst:
            src.backup(dst)
        src.close()
        dst.close()
        return Path(tmp).read_bytes()
    finally:
        os.remove(tmp)


def write(output, database: Path, keyfile: Path) -> dict:
    """Write a backup; ISDi must be unlocked. Returns a summary."""
    output = Path(output)
    keyfile_data = json.loads(Path(keyfile).read_text())
    db_bytes = _snapshot(Path(database), Path(database).parent)
    header = {
        "format": FORMAT,
        "made_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "database_size": len(db_bytes),
        "database_sha256": hashlib.sha256(db_bytes).hexdigest(),
        "keyfile": keyfile_data,
    }
    header_bytes = json.dumps(header, sort_keys=True).encode()
    digest = hashlib.sha256(header_bytes).digest()
    aes = AESGCM(crypto.derived_key("backup"))
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(MAGIC)
        f.write(struct.pack(">I", len(header_bytes)) + header_bytes)
        chunks = [db_bytes[i : i + CHUNK] for i in range(0, len(db_bytes), CHUNK)]
        chunks = chunks or [b""]
        for index, chunk in enumerate(chunks):
            nonce = os.urandom(12)
            sealed = aes.encrypt(
                nonce, chunk, _aad(digest, index, index == len(chunks) - 1)
            )
            f.write(struct.pack(">I", len(sealed)) + nonce + sealed)
    return {
        "made_at": header["made_at"],
        "database_size": len(db_bytes),
        "size": output.stat().st_size,
        "sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
    }


def read_header(path) -> dict:
    with open(path, "rb") as f:
        if f.read(len(MAGIC)) != MAGIC:
            raise BackupError(f"{path} is not an ISDi backup")
        (n,) = struct.unpack(">I", f.read(4))
        header = json.loads(f.read(n))
    if header.get("format") != FORMAT:
        raise BackupError(f"unsupported backup format {header.get('format')!r}")
    return header


def decrypt(path) -> bytes:
    """The database in a backup. The backup's keyfile must be unlocked
    (crypto.unlock on a copy of header["keyfile"])."""
    with open(path, "rb") as f:
        f.read(len(MAGIC))
        (n,) = struct.unpack(">I", f.read(4))
        header_bytes = f.read(n)
        records = []
        while size := f.read(4):
            (m,) = struct.unpack(">I", size)
            nonce, sealed = f.read(12), f.read(m)
            if len(sealed) != m:
                raise BackupError("the backup is cut short")
            records.append((nonce, sealed))
    header = json.loads(header_bytes)
    digest = hashlib.sha256(header_bytes).digest()
    aes = AESGCM(crypto.derived_key("backup"))
    parts = []
    for index, (nonce, sealed) in enumerate(records):
        last = index == len(records) - 1
        try:
            parts.append(aes.decrypt(nonce, sealed, _aad(digest, index, last)))
        except InvalidTag:
            raise BackupError(
                "the backup does not decrypt: it was altered or cut short, or "
                "the key does not match"
            )
    if not records:
        raise BackupError("the backup is cut short")
    db_bytes = b"".join(parts)
    if hashlib.sha256(db_bytes).hexdigest() != header["database_sha256"]:
        raise BackupError("the database in the backup does not match its hash")
    return db_bytes


def check_database(db_bytes: bytes, workdir: Path) -> None:
    fd, tmp = tempfile.mkstemp(dir=workdir, prefix=".restore-check-", suffix=".db")
    with os.fdopen(fd, "wb") as f:
        f.write(db_bytes)
    try:
        conn = sqlite3.connect(tmp)
        (result,) = conn.execute("PRAGMA integrity_check").fetchone()
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master")}
        conn.close()
    finally:
        os.remove(tmp)
    if result != "ok":
        raise BackupError(f"the database in the backup is damaged: {result}")
    if "clients_notes" not in tables:
        raise BackupError("the backup does not hold an ISDi database")
