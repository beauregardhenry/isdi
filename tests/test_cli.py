"""The command line: audit-log anchors, keys and passphrases, exports and
erasure, and the informational commands."""

import json
import os
import shutil
import sqlite3
import stat
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import click
import pytest
from click.testing import CliRunner

from isdi import audit, crypto, users
from isdi import cli as cli_mod
from isdi.config import get_config
from isdi.scanner import db
from tests.test_audit import _three_entries, fresh_log  # noqa: F401
from tests.test_config import run_cli  # noqa: F401
from tests.test_data_protection import _live_scan, phone  # noqa: F401


@pytest.fixture
def keyfile_copy(tmp_path, monkeypatch, keys):
    """A copy of the test keyfile, so a test may change its passphrase."""
    copy = tmp_path / "datakey.json"
    shutil.copy(get_config().keyfile, copy)
    monkeypatch.setattr(get_config(), "keyfile", copy)
    return copy


# Audit-log anchors


def _rewrite_from(conn, first_id):
    """What someone with the passphrase could do: change an entry and
    recompute the MACs of the chain from there, so verify() still passes."""
    rows = conn.execute("SELECT * FROM audit_log ORDER BY id").fetchall()
    prev = audit.GENESIS
    for row in rows:
        row = dict(row)
        if row["id"] >= first_id:
            if row["id"] == first_id:
                row["action"] = "rewritten"
            row["prev"] = prev
            row["mac"] = audit._entry_mac(row)
            conn.execute(
                "UPDATE audit_log SET action=?, prev=?, mac=? WHERE id=?",
                (row["action"], row["prev"], row["mac"], row["id"]),
            )
        prev = row["mac"]
    conn.commit()


def test_anchor_is_signed_private_and_holds_no_client_data(
    app, cli, fresh_log, tmp_path
):
    _three_entries()
    audit.record("note_saved", clientid="20260101_042", details={"x": "secret"})
    out = tmp_path / "anchor.json"
    res = cli("audit", "anchor", "-o", str(out))
    assert res.exit_code == 0, res.output
    assert "entry 5" in res.output
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    anchor = json.loads(out.read_text())
    assert anchor["format"] == audit.ANCHOR_FORMAT
    assert anchor["entries"] == 5 and anchor["newest_entry"]["id"] == 5
    assert set(anchor["newest_entry"]) == {"id", "time", "mac"}
    assert "20260101_042" not in out.read_text() and "secret" not in out.read_text()
    assert audit.entries()[-1]["action"] == "audit_anchored"
    assert cli("verify", str(out)).exit_code == 0  # signature

    res = cli("audit", "verify", "--anchor", str(out))
    assert res.exit_code == 0, res.output
    assert f"Matches anchor {out}" in res.output


def test_anchor_detects_a_rewritten_log_that_still_verifies(
    app, cli, fresh_log, tmp_path
):
    _three_entries()
    out = tmp_path / "anchor.json"
    assert cli("audit", "anchor", "-o", str(out)).exit_code == 0
    audit.record("later_action")

    _rewrite_from(fresh_log, 2)
    assert audit.verify()["ok"], "the rewrite should pass the chain check"
    res = cli("audit", "verify", "--anchor", str(out))
    assert res.exit_code == 1
    assert "entry 4 is not the one anchored: the log was rewritten" in res.output


def test_rewriting_after_the_anchor_is_not_detected_by_it(
    app, cli, fresh_log, tmp_path
):
    """The limit, stated in COURT_RECORDS.md: an anchor covers the log up
    to its entry. Newer anchors cover more."""
    _three_entries()
    out = tmp_path / "anchor.json"
    assert cli("audit", "anchor", "-o", str(out)).exit_code == 0
    audit.record("later_action")
    _rewrite_from(fresh_log, 5)
    assert cli("audit", "verify", "--anchor", str(out)).exit_code == 0


def test_anchor_detects_a_log_cut_short(app, cli, fresh_log, tmp_path):
    _three_entries()
    out = tmp_path / "anchor.json"
    assert cli("audit", "anchor", "-o", str(out)).exit_code == 0
    fresh_log.execute("DELETE FROM audit_log WHERE id >= 3")
    fresh_log.commit()
    assert audit.verify()["ok"]
    res = cli("audit", "verify", "--anchor", str(out))
    assert res.exit_code == 1 and "entry 4 is no longer in the log" in res.output


def test_anchor_must_be_signed_by_this_installation(app, cli, fresh_log, tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    import base64

    _three_entries()
    out = tmp_path / "anchor.json"
    assert cli("audit", "anchor", "-o", str(out)).exit_code == 0
    sig = Path(str(out) + ".sig")

    out.write_text(out.read_text().replace('"entries": 4', '"entries": 9'))
    res = cli("audit", "verify", "--anchor", str(out))
    assert res.exit_code == 1 and "does not match its signature" in res.output

    other = Ed25519PrivateKey.generate()
    pub = other.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    sig.write_text(
        json.dumps(
            {
                "algorithm": "Ed25519",
                "public_key": base64.b64encode(pub).decode(),
                "signature": base64.b64encode(other.sign(out.read_bytes())).decode(),
            }
        )
    )
    res = cli("audit", "verify", "--anchor", str(out))
    assert res.exit_code == 1 and "was signed by another key" in res.output

    sig.unlink()
    res = cli("audit", "verify", "--anchor", str(out))
    assert res.exit_code == 1 and "Cannot read anchor" in res.output


def test_anchor_refuses_to_overwrite_and_checks_the_format(
    app, cli, fresh_log, tmp_path
):
    out = tmp_path / "anchor.json"
    out.write_text("{}")
    res = cli("audit", "anchor", "-o", str(out))
    assert res.exit_code == 1 and "already exists" in res.output
    with app.app_context():
        assert audit.check_anchor({}) == "not an ISDi audit anchor"


@pytest.mark.parametrize(
    "days_ago, reminded", [(None, "never"), (2, None), (8, "8 days ago")]
)
def test_anchor_reminder(days_ago, reminded):
    now = datetime(2026, 10, 4, tzinfo=timezone.utc)
    last = (
        None
        if days_ago is None
        else {"id": 1, "time": (now - timedelta(days=days_ago)).isoformat()}
    )
    message = cli_mod._anchor_reminder(last, now=now)
    if reminded:
        assert f"last anchored {reminded}" in message
        assert "isdi audit anchor" in message
    else:
        assert message is None


def test_run_reminds_to_anchor(run_cli, fresh_log):  # noqa: F811
    users.create("someone", "Some One", "a long enough password")
    output, _ = run_cli()
    assert "audit log was last anchored never" in output


# Keys and passphrases


def _unlock_command(config):
    @click.command()
    def unlock():
        cli_mod._unlock(config)

    return unlock


def test_first_start_sets_up_encryption_and_shows_the_recovery_key(
    tmp_path, monkeypatch, keys
):
    monkeypatch.delenv("ISDI_PASSPHRASE", raising=False)
    config = SimpleNamespace(
        keyfile=tmp_path / "new.json", legacy_pii_key_file=tmp_path / "pii.key"
    )
    good = "a long enough passphrase"
    res = CliRunner().invoke(
        _unlock_command(config), input=f"short\nshort\n{good}\n{good}\nn\ny\n"
    )
    assert res.exit_code == 0, res.output
    assert "at least" in res.output  # the short one was refused
    assert "Recovery key:" in res.output
    assert res.output.count("Have you stored the recovery key?") == 2
    recovery = res.output.split("Recovery key: ")[1].split()[0]
    crypto.lock()
    crypto.unlock(config.keyfile, recovery_key=recovery)
    crypto.unlock(config.keyfile, passphrase=good)


def test_first_start_with_a_short_passphrase_in_the_environment_fails(
    tmp_path, monkeypatch, keys
):
    monkeypatch.setenv("ISDI_PASSPHRASE", "short")
    config = SimpleNamespace(
        keyfile=tmp_path / "new.json", legacy_pii_key_file=tmp_path / "pii.key"
    )
    res = CliRunner().invoke(_unlock_command(config))
    assert res.exit_code == 1 and "ISDI_PASSPHRASE: The passphrase" in res.output
    assert not config.keyfile.exists()


def test_passphrase_prompt_allows_three_tries(monkeypatch, passphrase, keys):
    monkeypatch.delenv("ISDI_PASSPHRASE", raising=False)
    command = _unlock_command(get_config())
    res = CliRunner().invoke(command, input=f"wrong one\n{passphrase}\n")
    assert res.exit_code == 0 and res.output.count("Wrong passphrase.") == 1

    res = CliRunner().invoke(command, input="a\nb\nc\n")
    assert res.exit_code == 1
    assert "isdi change-passphrase --recovery" in res.output


def test_wrong_passphrase_in_the_environment(cli, monkeypatch, keys):
    monkeypatch.setenv("ISDI_PASSPHRASE", "not the passphrase")
    res = cli("audit", "verify")
    assert res.exit_code == 1 and "ISDI_PASSPHRASE is not the passphrase" in res.output


def test_change_passphrase(cli, keyfile_copy, passphrase):
    new = "an entirely new passphrase"
    res = cli("change-passphrase", input=f"{passphrase}\n{new}\n{new}\n")
    assert res.exit_code == 0, res.output
    crypto.unlock(keyfile_copy, passphrase=new)
    with pytest.raises(crypto.UnlockError):
        crypto.unlock(keyfile_copy, passphrase=passphrase)

    res = cli("change-passphrase", input=f"{passphrase}\n{new}x\n{new}x\n")
    assert res.exit_code == 1


def test_change_passphrase_with_the_recovery_key(cli, tmp_path, monkeypatch, keys):
    keyfile = tmp_path / "k.json"
    recovery = crypto.setup(keyfile, "the first passphrase")
    monkeypatch.setattr(get_config(), "keyfile", keyfile)
    new = "the second passphrase"
    res = cli("change-passphrase", "--recovery", input=f"{recovery}\n{new}\n{new}\n")
    assert res.exit_code == 0, res.output
    crypto.unlock(keyfile, passphrase=new)


def test_commands_needing_keys_say_when_none_are_set_up(cli, tmp_path, monkeypatch):
    monkeypatch.setattr(get_config(), "keyfile", tmp_path / "missing.json")
    for args in (["change-passphrase"], ["signing-key"]):
        res = cli(*args)
        assert res.exit_code == 1 and "not set up yet" in res.output


def test_signing_key_of_a_keyfile_without_one(cli, tmp_path, monkeypatch):
    keyfile = tmp_path / "k.json"
    keyfile.write_text(json.dumps({"version": 1}))
    monkeypatch.setattr(get_config(), "keyfile", keyfile)
    res = cli("signing-key")
    assert res.exit_code == 1 and "No signing key yet" in res.output


# Exports, erasure, evidence


def test_export_to_the_screen_and_unknown_clients(app, cli, phone):  # noqa: F811
    clientid, _, _ = _live_scan(app, "Export Owner")
    res = cli("export", clientid)
    assert res.exit_code == 0, res.output
    assert json.loads(res.output)["scans"][0]["device_primary_user"] == ("Export Owner")
    for args in (["export", "nobody"], ["erase", "--yes", "nobody"]):
        res = cli(*args)
        assert res.exit_code == 1 and "Nothing is stored" in res.output


def test_erase_from_the_command_line(app, cli, phone):  # noqa: F811
    clientid, _, _ = _live_scan(app, "Erase Owner")
    res = cli("erase", "--yes", clientid)
    assert res.exit_code == 0, res.output
    assert "scan_res" in res.output
    with app.app_context():
        assert db.export_client(clientid)["scans"] == []


def test_evidence_list_and_export_errors(app, cli, tmp_path, fresh_log):
    res = cli("evidence", "list")
    assert res.exit_code == 0 and "No evidence copies are kept." in res.output
    res = cli("evidence", "export", "999", "-o", str(tmp_path / "p"))
    assert res.exit_code == 1 and "no scan 999" in res.output


def test_evidence_list_shows_kept_copies(app, cli, phone):  # noqa: F811
    from tests.test_evidence import _scan

    clientid, scanid, result = _scan(app, preserve=True)
    res = cli("evidence", "list", clientid)
    assert res.exit_code == 0
    assert f"scan {scanid}" in res.output and result["evidence_sha256"] in res.output
    assert "unredacted" not in res.output


def test_verify_of_something_unreadable(cli, tmp_path):
    lone = tmp_path / "lone.json"
    lone.write_text("{}")
    res = cli("verify", str(lone))
    assert res.exit_code == 1 and "Cannot verify" in res.output


def test_audit_show(app, cli, fresh_log):
    _three_entries()
    res = cli("audit", "show", "c1")
    assert res.exit_code == 0
    rows = json.loads(res.output)
    assert [r["details"] for r in rows] == [{"n": 0}, {"n": 1}, {"n": 2}]


# Informational commands, and the entry point


def test_info_and_paths(cli):
    config = get_config()
    res = cli("info")
    assert res.exit_code == 0 and str(config.database_path) in res.output
    res = cli("paths")
    assert res.exit_code == 0
    assert json.loads(res.output)["secrets"]["keyfile"] == str(config.keyfile)


RESET_PASSPHRASE = "the reset test passphrase"


@pytest.fixture
def isolated(tmp_path):
    """A separate ISDi home with a client in its database, and a way to run
    `isdi` there in a process of its own (reset deletes the database)."""
    # Link the suite's downloaded app-info.db into the new cache, so it is
    # not downloaded again.
    cache = tmp_path / "cache" / "isdi"
    cache.mkdir(parents=True)
    (cache / "app-info.db").symlink_to(
        Path(get_config().APP_INFO_SQLITE_FILE.replace("sqlite:///", "")).resolve()
    )
    env = dict(
        os.environ,
        XDG_DATA_HOME=str(tmp_path / "data"),
        XDG_CONFIG_HOME=str(tmp_path / "config"),
        XDG_CACHE_HOME=str(tmp_path / "cache"),
        ISDI_PASSPHRASE=RESET_PASSPHRASE,
        ISDI_OPERATOR="Reset Tester",
    )
    setup = (
        "from isdi import crypto, audit; from isdi.config import get_config;"
        "c = get_config(); crypto.setup(c.keyfile, %r);"
        "from isdi.app import create_app;"
        "app = create_app(c);"
        "from isdi.scanner import db;"
        "ctx = app.app_context(); ctx.push();"
        'db.get_db().execute("INSERT INTO clients_notes (clientid) '
        "VALUES ('20260101_009')\"); db.get_db().commit();"
        "(c.dumps_dir / 'x.txt').write_text('dump')"
    ) % RESET_PASSPHRASE
    subprocess.run([sys.executable, "-c", setup], env=env, check=True)

    def run(*args, input=None, passphrase=RESET_PASSPHRASE):
        return subprocess.run(
            [sys.executable, "-m", "isdi", *args],
            env=dict(env, ISDI_PASSPHRASE=passphrase),
            input=input,
            capture_output=True,
            text=True,
        )

    paths = json.loads(run("paths").stdout)
    return run, Path(paths["data"]["database"]), Path(paths["data"]["dumps"])


def test_reset_writes_a_backup_first_then_deletes(isolated, tmp_path):
    run, database, dumps = isolated
    backup_file = tmp_path / "before-reset.backup"
    res = run("reset", "-o", str(backup_file), input="DELETE EVERYTHING\n")
    assert res.returncode == 0, res.stderr + res.stdout
    assert "All client data has been deleted" in res.stdout
    assert not database.exists() and os.listdir(dumps) == []
    assert (database.parent.parent.parent / "cache" / "isdi" / "app-info.db").exists()

    # The backup holds the client and the reset itself.
    # The keys were kept, so restoring needs --replace.
    res = run("restore", "--replace", str(backup_file), input=f"{RESET_PASSPHRASE}\n")
    assert res.returncode == 0, res.stderr + res.stdout
    conn = sqlite3.connect(database)
    assert conn.execute("SELECT clientid FROM clients_notes").fetchall() == [
        ("20260101_009",)
    ]
    actions = [r[0] for r in conn.execute("SELECT action FROM audit_log")]
    assert actions[-2:] == ["data_reset", "restored_from_backup"]


@pytest.mark.parametrize(
    "args, input, passphrase, message",
    [
        (["reset"], "", RESET_PASSPHRASE, "Give either -o FILE"),
        (
            ["reset", "--no-backup", "-o", "x.backup"],
            "",
            RESET_PASSPHRASE,
            "Give either -o FILE",
        ),
        (["reset", "--no-backup"], "yes\n", RESET_PASSPHRASE, "Not confirmed"),
        (
            ["reset", "--no-backup"],
            "DELETE EVERYTHING\n",
            "a wrong passphrase!",
            "not the passphrase",
        ),
    ],
)
def test_reset_refuses_without_every_safeguard(
    isolated, args, input, passphrase, message
):
    run, database, dumps = isolated
    res = run(*args, input=input, passphrase=passphrase)
    assert res.returncode == 1 and message in res.stdout + res.stderr
    clients = sqlite3.connect(database).execute("SELECT clientid FROM clients_notes")
    assert clients.fetchall() == [("20260101_009",)]


def test_reset_without_a_backup_when_asked(isolated):
    run, database, _ = isolated
    res = run("reset", "--no-backup", input="DELETE EVERYTHING\n")
    assert res.returncode == 0, res.stderr + res.stdout
    assert not database.exists()


@pytest.mark.parametrize(
    "error, code, message",
    [(KeyboardInterrupt, 0, "Goodbye"), (RuntimeError("boom"), 1, "Error: boom")],
)
def test_main_handles_interrupts_and_errors(monkeypatch, capsys, error, code, message):
    def fail():
        raise error

    monkeypatch.setattr(cli_mod, "cli", fail)
    with pytest.raises(SystemExit) as exit_:
        cli_mod.main()
    assert exit_.value.code == code
    captured = capsys.readouterr()
    assert message in captured.out + captured.err


@pytest.fixture
def serving(tmp_path, monkeypatch):
    """Pretend `isdi run` is serving this data from another process."""
    from isdi.cli import common

    pidfile = tmp_path / "isdi-run.pid"
    monkeypatch.setattr(common, "_server_pid_file", lambda config: pidfile)
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    pidfile.write_text(str(proc.pid))
    yield pidfile, proc
    proc.kill()
    proc.wait()


def test_reset_and_restore_refuse_while_isdi_runs(app, cli, serving, tmp_path):
    for args in (["reset", "--no-backup"], ["restore", "--replace", __file__]):
        res = cli(*args, input="DELETE EVERYTHING\n")
        assert res.exit_code == 1 and "ISDi is running" in res.output, args
    # The database is untouched.
    assert get_config().database_path.exists()


def test_a_pid_file_left_by_a_crash_is_ignored(serving):
    from isdi.cli import common

    pidfile, proc = serving
    assert common.server_pid(get_config()) == proc.pid
    proc.kill()
    proc.wait()
    assert common.server_pid(get_config()) is None
    pidfile.write_text("not a pid")
    assert common.server_pid(get_config()) is None


def test_run_marks_itself_as_serving(run_cli, tmp_path, monkeypatch):  # noqa: F811
    import atexit

    from isdi.cli import common

    pidfile = tmp_path / "isdi-run.pid"
    monkeypatch.setattr(common, "_server_pid_file", lambda config: pidfile)
    at_exit = []
    monkeypatch.setattr(atexit, "register", at_exit.append)
    run_cli()
    assert pidfile.read_text() == str(os.getpid())
    at_exit[0]()
    assert not pidfile.exists()
