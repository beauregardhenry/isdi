"""Client data at rest: encrypted in the database, raw dumps never kept,
plaintext leftovers removed, and the tools for access and erasure."""

import json
import os
import sqlite3
import stat
import uuid
from pathlib import Path

import pytest
from click.testing import CliRunner

import isdi.scanner as scanner
from isdi import crypto
from isdi.config import get_config
from isdi.scanner import db
from tests.test_consult import _valid_form_data
from tests.test_scanner_pipeline import FAKE_ADB, SERIAL, STALKER, _fake_tool


def _database_bytes():
    return Path(db.DATABASE).read_bytes()


def _phone_dump_files():
    """This phone's raw dump files (other tests use the directory too)."""
    prefix = get_config().hmac_serial(SERIAL)
    return sorted(f for f in os.listdir(get_config().DUMP_DIR) if f.startswith(prefix))


@pytest.fixture
def phone(tmp_path, monkeypatch):
    """The app's Android scanner, talking to a fake adb."""
    from isdi.web.view import index

    monkeypatch.setattr(index.android, "cli", _fake_tool(tmp_path, "adb", FAKE_ADB))
    monkeypatch.setattr(scanner.AppScanner, "app_info_conn", None)
    return index.android


def _live_scan(app, owner):
    from isdi.web.view import scan as scan_view

    clientid = f"dp_{uuid.uuid4().hex[:8]}"
    with app.test_request_context():
        result, status = scan_view._run_live_scan(clientid, "android", owner, SERIAL)
    return clientid, result, status


def test_live_scan_keeps_no_dump_and_no_plaintext(app, phone):
    owner = f"Owner-{uuid.uuid4().hex[:6]}"
    clientid, result, status = _live_scan(app, owner)
    assert status == 200 and STALKER in result["apps"]

    assert _phone_dump_files() == [], "the raw dump was kept"
    stored = _database_bytes()
    for secret in (owner, "Pixel 8", STALKER, "2026-09-01 12:00:00"):
        assert secret.encode() not in stored, f"{secret!r} stored in the clear"

    # What the details page needs was kept, encrypted, with the scan.
    with app.app_context():
        details = db.app_details_from_scan(result["scanid"], [STALKER])
    assert details[STALKER]["firstInstallTime"] == "2026-09-01 12:00:00"


def test_failed_scan_still_deletes_the_dump(app, phone, monkeypatch):
    from isdi.scanner import blocklist

    def boom(*a, **k):
        assert _phone_dump_files(), "the dump should exist during the scan"
        raise RuntimeError("classification failed")

    monkeypatch.setattr(blocklist, "app_title_and_flag", boom)
    with pytest.raises(RuntimeError):
        _live_scan(app, "x")
    assert _phone_dump_files() == []


def test_consultation_notes_are_encrypted(app, no_csrf):
    c = app.test_client()
    clientid = f"dp_{uuid.uuid4().hex[:8]}"
    with c.session_transaction() as s:
        s["clientid"] = clientid
    note = f"NOTE-{uuid.uuid4().hex}"
    c.post("/form/", data=_valid_form_data(general_notes=note))
    assert note.encode() not in _database_bytes()
    with app.app_context():
        [row] = db.export_client(clientid)["notes"]
    assert row["general_notes"] == note


LEGACY_PLAINTEXT = "Legacy plaintext note 7f3a"


def test_migration_encrypts_an_old_plaintext_database(tmp_path):
    """A database from before encryption: CHECK constraints, no details
    column, plaintext values."""
    legacy_schema = (
        db.SCHEMA_SQL[: db.SCHEMA_SQL.index("-- Append-only record")]
        .replace(
            "\tPRIMARY KEY (id)\n);",
            "\tPRIMARY KEY (id),\n\tCHECK (recorded IN ('', 'Yes', 'No'))\n);",
            1,
        )
        .replace("  details TEXT,\n", "")
        .replace("  operator TEXT,\n", "")
    )
    path = tmp_path / "old.db"
    conn = sqlite3.connect(path)
    conn.executescript(legacy_schema)
    conn.execute(
        "INSERT INTO clients_notes (id, clientid, recorded, general_notes) "
        "VALUES (1, '20250101_001', 'Yes', ?)",
        (LEGACY_PLAINTEXT,),
    )
    conn.execute(
        "INSERT INTO scan_res (clientid, serial, device, device_model, "
        "device_primary_user) VALUES ('20250101_001', 'h', 'android', "
        "'Legacy Model X', 'Legacy Owner')"
    )
    conn.execute(
        "INSERT INTO app_info (scanid, appid, flags) VALUES (1, 'com.legacy.spy', '[]')"
    )
    conn.commit()

    db.migrate(conn)
    db.migrate(conn)  # idempotent
    conn.close()

    raw = path.read_bytes()
    for secret in (
        LEGACY_PLAINTEXT,
        "Legacy Model X",
        "Legacy Owner",
        "com.legacy.spy",
    ):
        assert secret.encode() not in raw, f"{secret!r} left in the clear"

    conn = sqlite3.connect(path)
    conn.row_factory = db.make_dicts
    notes = conn.execute("SELECT * FROM clients_notes").fetchone()
    assert notes["general_notes"] == LEGACY_PLAINTEXT and notes["recorded"] == "Yes"
    scan = conn.execute("SELECT * FROM scan_res").fetchone()
    assert scan["device_primary_user"] == "Legacy Owner"
    sql = conn.execute(
        "SELECT sql FROM sqlite_master WHERE name='clients_notes'"
    ).fetchone()["sql"]
    assert "CHECK" not in sql
    assert "details" in [r["name"] for r in conn.execute("PRAGMA table_info(app_info)")]


def test_migration_adds_the_unredacted_flag_to_kept_evidence(tmp_path):
    """A version 3 database: evidence table without the unredacted column.
    Copies kept then were all redacted."""
    v3 = db.SCHEMA_SQL.replace("  unredacted INTEGER NOT NULL DEFAULT 0,\n", "")
    assert v3 != db.SCHEMA_SQL
    path = tmp_path / "v3.db"
    conn = sqlite3.connect(path)
    conn.executescript(v3)
    conn.execute(
        "INSERT INTO evidence (scanid, created, dump_sha256) VALUES (1, 't', 'h')"
    )
    conn.execute("PRAGMA user_version = 3")
    conn.commit()

    db.migrate(conn)
    db.migrate(conn)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == db.SCHEMA_VERSION
    assert conn.execute("SELECT unredacted FROM evidence").fetchone()[0] == 0


def test_plaintext_leftovers_are_removed(tmp_path, monkeypatch):
    from isdi.data_protection import purge_plaintext_files

    cfg = get_config()
    purge_plaintext_files(cfg)  # start from an empty dump directory
    Path(cfg.DUMP_DIR, "abc_android.txt").write_text("raw dump")
    Path(cfg.DUMP_DIR, "abc_android.json").write_text("{}")
    Path(cfg.reports_dir, "20250101_001.csv").write_text("appid\ncom.x\n")
    legacy_key = tmp_path / "pii.key"
    legacy_key.write_bytes(b"k" * 32)
    monkeypatch.setattr(cfg, "legacy_pii_key_file", legacy_key)

    removed = purge_plaintext_files(cfg)
    assert removed == {"dumps": 2, "reports": 1, "legacy_pii_key": 1}
    assert os.listdir(cfg.DUMP_DIR) == []
    assert not list(Path(cfg.reports_dir).glob("*.csv"))
    assert not legacy_key.exists()


def test_legacy_key_is_kept_until_the_keyfile_exists(tmp_path, monkeypatch):
    from isdi.data_protection import purge_plaintext_files

    cfg = get_config()
    legacy_key = tmp_path / "pii.key"
    legacy_key.write_bytes(b"k" * 32)
    monkeypatch.setattr(cfg, "legacy_pii_key_file", legacy_key)
    monkeypatch.setattr(cfg, "keyfile", tmp_path / "missing.json")
    purge_plaintext_files(cfg)
    assert legacy_key.exists()


def test_database_and_data_dirs_are_private(app):
    cfg = get_config()
    assert stat.S_IMODE(Path(db.DATABASE).stat().st_mode) == 0o600
    for d in (cfg.dirs["data"], cfg.dirs["config"], Path(cfg.DUMP_DIR)):
        assert stat.S_IMODE(Path(d).stat().st_mode) == 0o700, d


def test_pages_are_not_cached_by_the_browser(client):
    assert client.get("/").headers["Cache-Control"] == "no-store"


def test_app_will_not_start_locked():
    from isdi.app import create_app

    saved = crypto._state()
    crypto.lock()
    try:
        with pytest.raises(crypto.LockedError):
            create_app(get_config())
    finally:
        crypto._restore(saved)


@pytest.fixture
def cli_runner(monkeypatch):
    from isdi import cli

    monkeypatch.delenv("ISDI_PASSPHRASE", raising=False)
    saved = crypto._state()
    yield lambda *args, **kw: CliRunner().invoke(cli.cli, list(args), **kw)
    crypto._restore(saved)


def test_first_start_sets_up_a_passphrase_and_shows_the_recovery_key(
    cli_runner, tmp_path, monkeypatch
):
    cfg = get_config()
    monkeypatch.setattr(cfg, "keyfile", tmp_path / "datakey.json")
    res = cli_runner(
        "export",
        "nobody",
        input="too short\ntoo short\na long new passphrase\na long new passphrase\ny\n",
    )
    assert "at least 12 characters" in res.output
    assert "Recovery key:" in res.output
    assert (tmp_path / "datakey.json").exists()
    recovery = res.output.split("Recovery key:")[1].split()[0]
    crypto.lock()
    crypto.unlock(cfg.keyfile, recovery_key=recovery)


def test_wrong_passphrase_three_times_refuses(cli_runner):
    res = cli_runner("export", "nobody", input="nope\nnope\nnope\n")
    assert res.exit_code == 1 and res.output.count("Wrong passphrase") >= 3


def test_cli_export_and_erase(app, cli_runner, passphrase, tmp_path, phone):
    clientid, result, _ = _live_scan(app, "Owner")
    out = tmp_path / "export.json"
    res = cli_runner("export", clientid, "-o", str(out), input=passphrase + "\n")
    assert res.exit_code == 0, res.output
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    data = json.loads(out.read_text())
    assert data["scans"][0]["device_primary_user"] == "Owner"

    res = cli_runner("erase", clientid, "--yes", input=passphrase + "\n")
    assert res.exit_code == 0, res.output
    res = cli_runner("export", clientid, input=passphrase + "\n")
    assert res.exit_code == 1 and "Nothing is stored" in res.output


def test_dump_details_survive_values_json_cannot_store(phone):
    """Details are stored as JSON; a set or a date in the parse must not
    abort the scan."""
    import datetime

    class Dump:
        def info(self, appid):
            return {"perms": {"b", "a"}, "when": datetime.date(2026, 1, 2)}

    phone.ddump = Dump()
    try:
        details = phone.dump_details(["x"])
    finally:
        phone.ddump = None
    assert sorted(details["x"]["perms"]) == ["a", "b"]
    assert details["x"]["when"] == "2026-01-02"


def test_dumps_are_kept_in_private_storage_and_old_shared_ones_deleted(
    tmp_path, monkeypatch
):
    """On Termux the data dir is shared storage: dumps must not go there."""
    from isdi import config as config_mod
    from isdi.data_protection import purge_plaintext_files

    monkeypatch.setenv("PREFIX", "/data/data/com.termux/files/usr")
    monkeypatch.setattr(config_mod.Path, "home", lambda: tmp_path)
    dirs = config_mod.get_platform_dirs()
    assert "storage" in dirs["data"].parts and "storage" not in dirs["local_data"].parts

    cfg = get_config()
    monkeypatch.setattr(cfg, "dirs", dirs)
    cfg.setup_paths()
    try:
        assert cfg.dumps_dir == dirs["local_data"] / "dumps"
        assert "storage" not in cfg.dumps_dir.parts
        shared = dirs["data"] / "dumps"
        assert cfg.legacy_dumps_dirs == [shared]
        shared.mkdir(parents=True, exist_ok=True)
        (shared / "abc_android.txt").write_text("raw dump")
        monkeypatch.setattr(cfg, "DUMP_DIR", str(cfg.dumps_dir))
        from isdi import scanner

        monkeypatch.setattr(scanner.cfg, "DUMP_DIR", str(cfg.dumps_dir))
        assert purge_plaintext_files(cfg)["dumps"] == 1
        assert list(shared.iterdir()) == []
    finally:
        monkeypatch.undo()
        get_config().setup_paths()


def test_elsewhere_dumps_stay_where_they_were():
    cfg = get_config()
    assert cfg.dirs["data"] == cfg.dirs["local_data"]
    assert cfg.dumps_dir == cfg.dirs["data"] / "dumps"
    assert cfg.legacy_dumps_dirs == []
