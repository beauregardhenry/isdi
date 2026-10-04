"""Encrypted backups: what they hold, and that a restore brings back exactly
that, refusing anything altered, cut short or locked with another key."""

import json
import os
import sqlite3
import stat
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from click.testing import CliRunner

from isdi import audit, backup, crypto
from isdi import cli as cli_mod
from isdi.config import get_config
from isdi.scanner import db
from tests.test_data_protection import _live_scan, phone  # noqa: F401

KEYFILE = get_config().keyfile  # the suite's, before any test moves it


@pytest.fixture
def cli(monkeypatch, passphrase):
    monkeypatch.setenv("ISDI_PASSPHRASE", passphrase)
    saved = audit.operator()
    yield lambda *a, **kw: CliRunner().invoke(cli_mod.cli, list(a), **kw)
    audit.set_operator(saved)


@pytest.fixture
def new_home(tmp_path, monkeypatch):
    """Where a restore writes: an empty database and keyfile location, as
    on a new computer."""
    cfg = get_config()
    home = tmp_path / "new"
    home.mkdir()
    monkeypatch.setattr(cfg, "database_path", home / "database.db")
    monkeypatch.setattr(cfg, "keyfile", home / "datakey.json")
    return home


@pytest.fixture
def made(app, cli, phone, tmp_path):  # noqa: F811
    """A backup of the suite's data, holding a client scanned just before."""
    owner = f"Backup Owner {uuid.uuid4().hex[:6]}"
    clientid, result, _ = _live_scan(app, owner)
    out = tmp_path / "isdi.backup"
    res = cli("backup", "-o", str(out))
    assert res.exit_code == 0, res.output
    return out, clientid, owner, result["scanid"]


def _rows(path, sql, args=()):
    conn = sqlite3.connect(path)
    conn.row_factory = db.make_dicts
    try:
        return conn.execute(sql, args).fetchall()
    finally:
        conn.close()


def test_backup_is_private_and_holds_nothing_in_the_clear(made):
    out, clientid, owner, _ = made
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    data = out.read_bytes()
    for secret in (owner, clientid, "Pixel 8", "SQLite format 3"):
        assert secret.encode() not in data, secret
    header = backup.read_header(out)
    assert header["keyfile"] == json.loads(KEYFILE.read_text())


def test_backup_is_recorded_and_refuses_to_overwrite(app, made, cli):
    out, _, _, _ = made
    with app.app_context():
        assert audit.entries()[-1]["action"] == "backup_made"
    res = cli("backup", "-o", str(out))
    assert res.exit_code == 1 and "already exists" in res.output


def test_restore_on_a_new_computer(made, cli, new_home, passphrase):
    out, clientid, owner, scanid = made
    res = cli("restore", str(out), input=f"{passphrase}\n")
    assert res.exit_code == 0, res.output
    restored = new_home / "database.db"
    assert stat.S_IMODE(restored.stat().st_mode) == 0o600
    assert stat.S_IMODE((new_home / "datakey.json").stat().st_mode) == 0o600
    scan = _rows(restored, "SELECT * FROM scan_res WHERE id=?", (scanid,))[0]
    assert scan["clientid"] == clientid and scan["device_primary_user"] == owner
    log = _rows(restored, "SELECT * FROM audit_log ORDER BY id")
    assert [e["action"] for e in log[-2:]] == ["backup_made", "restored_from_backup"]
    assert log[-1]["operator"] == "Test Operator"
    assert log[-1]["details"]["replaced_existing_data"] is False
    assert not [p for p in new_home.iterdir() if p.name.startswith(".restore")]


def test_restore_with_the_recovery_key(tmp_path, new_home, cli, keys):
    """A backup of another installation, restored with its recovery key."""
    other_key, other_db = tmp_path / "k.json", tmp_path / "o.db"
    recovery = crypto.setup(other_key, "the other passphrase")
    conn = sqlite3.connect(other_db)
    conn.executescript(db.SCHEMA_SQL)
    conn.execute(
        "INSERT INTO clients_notes (clientid, general_notes) VALUES (?, ?)",
        ("20260101_007", crypto.encrypt("general_notes", "restored note")),
    )
    conn.commit()
    conn.close()
    out = tmp_path / "other.backup"
    backup.write(out, other_db, other_key)
    crypto._restore(keys)

    res = cli("restore", "--recovery", str(out), input=f"{recovery}\n")
    assert res.exit_code == 0, res.output
    crypto.unlock(new_home / "datakey.json", passphrase="the other passphrase")
    notes = _rows(new_home / "database.db", "SELECT * FROM clients_notes")
    assert notes[0]["general_notes"] == "restored note"


@pytest.fixture
def keys():
    saved = crypto._state()
    yield saved
    crypto._restore(saved)


def test_restore_keeps_the_current_data_when_replacing(made, cli, new_home, passphrase):
    out, _, _, _ = made
    (new_home / "database.db").write_bytes(b"current db")
    (new_home / "datakey.json").write_text("{}")
    res = cli("restore", str(out), input=f"{passphrase}\n")
    assert res.exit_code == 1 and "--replace" in res.output
    assert (new_home / "database.db").read_bytes() == b"current db"

    res = cli("restore", "--replace", str(out), input=f"{passphrase}\n")
    assert res.exit_code == 0, res.output
    kept = sorted(
        p.name.split(".before-restore-")[0]
        for p in new_home.iterdir()
        if ".before-restore-" in p.name
    )
    assert kept == ["database.db", "datakey.json"]
    assert (new_home / "database.db").read_bytes()[:15] == b"SQLite format 3"


def test_restore_refuses_a_wrong_passphrase(made, cli, new_home):
    out, _, _, _ = made
    res = cli("restore", str(out), input="not the passphrase\n")
    assert res.exit_code == 1 and "not the passphrase or recovery key" in res.output
    assert list(new_home.iterdir()) == []


def _damage(path, how):
    data = bytearray(path.read_bytes())
    if how == "flip":
        data[-20] ^= 0x01
    elif how == "truncate":
        data = data[: len(data) - 100]
    elif how == "drop_last_part":
        # Cut exactly after a complete part: the previous one was not
        # sealed as the last, so this must still be refused.
        offset = len(backup.MAGIC)
        n = int.from_bytes(data[offset : offset + 4], "big")
        offset += 4 + n
        first = int.from_bytes(data[offset : offset + 4], "big")
        data = data[: offset + 4 + 12 + first]
    elif how == "magic":
        data[:4] = b"XXXX"
    path.write_bytes(bytes(data))


@pytest.mark.parametrize(
    "how, message",
    [
        ("flip", "does not decrypt"),
        ("truncate", "cut short"),
        ("drop_last_part", "does not decrypt"),
        ("magic", "not an ISDi backup"),
    ],
)
def test_restore_refuses_damaged_backups(
    made, cli, new_home, passphrase, monkeypatch, how, message
):
    out, _, _, _ = made
    if how == "drop_last_part":
        monkeypatch.setattr(backup, "CHUNK", 4096)  # several parts
        out = out.with_name("small-chunks.backup")
        backup.write(out, Path(db.DATABASE), KEYFILE)
    _damage(out, how)
    res = cli("restore", str(out), input=f"{passphrase}\n")
    assert res.exit_code == 1 and message in res.output, res.output
    assert list(new_home.iterdir()) == []


def test_restore_refuses_a_backup_of_something_else(tmp_path, cli, new_home, keys):
    other_key, other_db = tmp_path / "k.json", tmp_path / "o.db"
    crypto.setup(other_key, "the other passphrase")
    sqlite3.connect(other_db).execute("CREATE TABLE t (x)").connection.commit()
    out = tmp_path / "other.backup"
    backup.write(out, other_db, other_key)
    crypto._restore(keys)
    res = cli("restore", str(out), input="the other passphrase\n")
    assert res.exit_code == 1 and "does not hold an ISDi database" in res.output


@pytest.mark.parametrize(
    "days_ago, reminded", [(None, "never"), (3, None), (10, "10 days ago")]
)
def test_backup_reminder(days_ago, reminded):
    now = datetime(2026, 10, 4, tzinfo=timezone.utc)
    last = (
        None
        if days_ago is None
        else {"id": 1, "time": (now - timedelta(days=days_ago)).isoformat()}
    )
    message = cli_mod._backup_reminder(last, now=now)
    if reminded:
        assert f"last backup was made {reminded}" in message
    else:
        assert message is None


def test_restored_files_never_linger_in_temporary_places(made, cli, new_home):
    out, _, _, _ = made
    cli("restore", str(out), input="wrong passphrase!\n")
    leftovers = [
        p
        for p in Path(get_config().keyfile).parent.rglob("*")
        if ".restore-" in p.name or ".backup-" in p.name
    ]
    assert leftovers == []
    assert not any(".backup-" in n for n in os.listdir(Path(db.DATABASE).parent))
