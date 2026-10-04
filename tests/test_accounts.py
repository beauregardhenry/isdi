"""Accounts and signing in: every page needs a signed-in user, failed
sign-ins lock an account, sessions end when idle, and the audit log names
the user who acted."""

import json
import sqlite3
import time
import uuid
from datetime import timedelta
from pathlib import Path

import pytest
from click.testing import CliRunner

from isdi import audit, users
from isdi import cli as cli_mod
from isdi.scanner import db
from tests.conftest import TEST_PASSWORD, TEST_USERNAME
from tests.test_audit import fresh_log  # noqa: F401
from tests.test_config import run_cli  # noqa: F401

PASSWORD = "a long enough password"


@pytest.fixture
def account(app):
    """A new account of its own, for tests that lock or disable it."""
    username = f"u{uuid.uuid4().hex[:10]}"
    with app.app_context():
        users.create(username, "Alex Advocate", PASSWORD)
    return username


@pytest.fixture
def anon(app):
    return app.test_client(signed_in=False)


def _sign_in(client, username, password=PASSWORD, next_=""):
    return client.post(
        "/login", data={"username": username, "password": password, "next": next_}
    )


def _actions(app, n=10):
    with app.app_context():
        return [(e["action"], e["operator"], e["details"]) for e in audit.entries()][
            -n:
        ]


# Pages need a signed-in user


def test_pages_redirect_to_sign_in(anon):
    r = anon.get("/")
    assert r.status_code == 302 and "/login?next=" in r.headers["Location"]
    assert anon.get("/scan/saved/1").status_code == 302


def test_requests_from_scripts_get_401(anon, no_csrf):
    for r in (
        anon.post("/scan/start", data={"device": "test", "device_owner": "o"}),
        anon.get("/scan/status/abc"),
    ):
        assert r.status_code == 401 and r.get_json() == {
            "error": "Please sign in again."
        }


def test_sign_in_page_and_static_files_are_open(anon):
    page = anon.get("/login")
    assert page.status_code == 200 and b"Sign in to ISDi" in page.data
    assert b'name="csrf_token"' in page.data
    assert anon.get("/static/style.css").status_code == 200


def test_sign_in_needs_the_csrf_token(app, anon, account):
    r = _sign_in(anon, account)
    assert r.status_code == 400  # the form token is missing


def test_signed_in_pages_show_the_user(client):
    page = client.get("/")
    assert page.status_code == 200
    assert b"Signed in as Test Operator (tester)" in page.data


# Signing in and out


def test_sign_in_and_out(app, anon, account, no_csrf):
    r = _sign_in(anon, account, next_="/instruction")
    assert r.status_code == 302 and r.headers["Location"] == "/instruction"
    assert anon.get("/").status_code == 200
    label = f"Alex Advocate ({account})"
    assert ("login", label, None) in _actions(app)

    r = anon.post("/logout")
    assert r.status_code == 302 and r.headers["Location"] == "/login"
    assert anon.get("/").status_code == 302
    assert ("logout", label, {"reason": "signed out"}) in _actions(app)


def test_signing_out_ends_copies_of_the_session(app, account, no_csrf):
    this = app.test_client(signed_in=False)
    _sign_in(this, account)
    with this.session_transaction() as s:
        stolen = dict(s)
    this.post("/logout")
    replay = app.test_client(signed_in=False)
    with replay.session_transaction() as s:
        s.update(stolen)
    assert replay.get("/").status_code == 302
    assert _sign_in(this, account).status_code == 302
    assert this.get("/").status_code == 200, "a new sign-in works"


@pytest.mark.parametrize("target", ["//evil.example/x", "https://evil.example/", ""])
def test_sign_in_never_redirects_off_site(anon, account, no_csrf, target):
    r = _sign_in(anon, account, next_=target)
    assert r.headers["Location"] == "/"


def test_wrong_and_unknown_sign_ins_look_the_same(app, anon, account, no_csrf):
    wrong = _sign_in(anon, account, password="not the password")
    unknown = _sign_in(anon, "nobody-here", password="not the password")
    assert wrong.status_code == unknown.status_code == 401
    message = b"Wrong username or password, or the account is locked or disabled."
    assert message in wrong.data and message in unknown.data
    assert anon.get("/").status_code == 302
    failed = [d for a, _, d in _actions(app) if a == "login_failed"]
    assert {"username": account, "reason": "wrong"} in failed
    assert {"reason": "unknown"} in failed  # the unknown name is not recorded


def test_usernames_are_not_case_sensitive(anon, account, no_csrf):
    assert _sign_in(anon, account.upper()).status_code == 302


def test_repeated_failures_lock_the_account(app, anon, account, no_csrf, monkeypatch):
    for _ in range(users.MAX_FAILED):
        assert _sign_in(anon, account, password="wrong password!").status_code == 401
    assert _sign_in(anon, account).status_code == 401, "locked: even the password"
    with app.app_context():
        assert users.is_locked(users.by_username(account))
    assert "user_locked" in [a for a, _, _ in _actions(app)]

    later = users._now() + timedelta(minutes=users.LOCKOUT_MINUTES, seconds=1)
    monkeypatch.setattr(users, "_now", lambda: later)
    assert _sign_in(anon, account).status_code == 302


def test_a_success_resets_the_failure_count(app, anon, account, no_csrf):
    for _ in range(users.MAX_FAILED - 1):
        _sign_in(anon, account, password="wrong password!")
    assert _sign_in(anon, account).status_code == 302
    with app.app_context():
        assert users.by_username(account)["failed_attempts"] == 0


# Sessions end


def test_idle_sessions_end(app, anon, account, no_csrf):
    _sign_in(anon, account)
    with anon.session_transaction() as s:
        s["last_seen"] = time.time() - 60 * 16
    r = anon.get("/")
    assert r.status_code == 302
    page = anon.get("/login")
    assert b"signed out after a period of inactivity" in page.data
    assert ("logout", f"Alex Advocate ({account})", {"reason": "idle"}) in _actions(app)


def test_the_idle_limit_can_be_set(app, anon, account, no_csrf, monkeypatch):
    monkeypatch.setitem(app.config, "ISDI_IDLE_MINUTES", 60)
    _sign_in(anon, account)
    with anon.session_transaction() as s:
        s["last_seen"] = time.time() - 60 * 30
    assert anon.get("/").status_code == 200


def test_activity_on_the_page_keeps_the_session(app, anon, account, no_csrf):
    _sign_in(anon, account)
    with anon.session_transaction() as s:
        s["last_seen"] = time.time() - 60 * 14
    assert anon.get("/session/ping").status_code == 204
    with anon.session_transaction() as s:
        assert time.time() - s["last_seen"] < 5
    js = (Path(app.static_folder) / "myjscript.js").read_text()
    assert "$.get('/session/ping')" in js
    assert anon.get("/session/ping").status_code == 204


def test_disabling_an_account_ends_its_sessions(app, anon, account, no_csrf):
    _sign_in(anon, account)
    with app.app_context():
        users.set_disabled(account, True)
    assert anon.get("/").status_code == 302
    assert _sign_in(anon, account).status_code == 401
    with app.app_context():
        users.set_disabled(account, False)
    assert _sign_in(anon, account).status_code == 302


def test_changing_the_password_ends_other_sessions(app, account, no_csrf):
    this, other = (app.test_client(signed_in=False) for _ in range(2))
    _sign_in(this, account)
    _sign_in(other, account)
    new = "a different long password"
    r = this.post(
        "/account/password", data={"current": PASSWORD, "new": new, "confirm": new}
    )
    assert r.status_code == 200 and b"Password changed." in r.data
    assert this.get("/").status_code == 200
    assert other.get("/").status_code == 302
    assert _sign_in(other, account, password=new).status_code == 302


@pytest.mark.parametrize(
    "form, error",
    [
        (
            {"current": "wrong password!", "new": "x" * 12, "confirm": "x" * 12},
            b"wrong",
        ),
        ({"current": PASSWORD, "new": "x" * 12, "confirm": "y" * 12}, b"do not match"),
        ({"current": PASSWORD, "new": "short", "confirm": "short"}, b"at least 12"),
    ],
)
def test_password_change_errors(app, account, no_csrf, form, error):
    c = app.test_client(signed_in=False)
    _sign_in(c, account)
    r = c.post("/account/password", data=form)
    assert r.status_code == 400 and error in r.data
    assert c.get("/account/password").status_code == 200


# Who acted


def test_web_actions_are_recorded_under_the_signed_in_user(app, client, no_csrf):
    from tests.test_consult import _valid_form_data

    with client.session_transaction() as s:
        s["clientid"] = cid = f"acct_{uuid.uuid4().hex[:8]}"
    client.post("/form/", data=_valid_form_data())
    with app.app_context():
        entries = audit.entries(cid)
    assert entries and entries[-1]["operator"] == "Test Operator (tester)"


def test_background_scans_are_recorded_under_the_user_who_started_them(
    app, client, no_csrf
):
    with client.session_transaction() as s:
        s["clientid"] = cid = f"acct_{uuid.uuid4().hex[:8]}"
    r = client.post(
        "/scan/start",
        data={"device": "test", "device_owner": "Owner", "devid": "testdevice1"},
    )
    job = r.get_json()["job_id"]
    for _ in range(100):
        status = client.get(f"/scan/status/{job}").get_json()
        if status["status"] != "running":
            break
        time.sleep(0.05)
    assert status["status"] == "done", status
    with app.app_context():
        entries = audit.entries(cid)
        scan = db.query_db("SELECT * FROM scan_res WHERE clientid=?", (cid,), one=True)
    assert entries[0]["operator"] == "Test Operator (tester)"
    assert scan["operator"] == "Test Operator (tester)"


# What is stored


def test_only_a_hash_of_the_password_and_an_encrypted_name_are_stored(app):
    name = f"Name {uuid.uuid4().hex[:8]}"
    password = f"password {uuid.uuid4().hex}"
    with app.app_context():
        users.create(f"u{uuid.uuid4().hex[:8]}", name, password)
    stored = Path(db.DATABASE).read_bytes()
    assert password.encode() not in stored and name.encode() not in stored


@pytest.mark.parametrize(
    "username, name, password, error",
    [
        ("Bad Name", "N", PASSWORD, "A username is"),
        ("x", "N", PASSWORD, "A username is"),
        (TEST_USERNAME, "N", PASSWORD, "already an account"),
        ("newname", " ", PASSWORD, "full name"),
        ("newname", "N", "short", "at least 12"),
    ],
)
def test_account_rules(app, username, name, password, error):
    with app.app_context(), pytest.raises(users.AccountError, match=error):
        users.create(username, name, password)


def test_changes_to_unknown_accounts_fail(app):
    with app.app_context(), pytest.raises(users.AccountError, match="no account"):
        users.set_disabled("nobody-here", True)


def test_migration_adds_the_users_table(tmp_path):
    v4 = db.SCHEMA_SQL[: db.SCHEMA_SQL.index("-- Staff accounts")]
    path = tmp_path / "v4.db"
    conn = sqlite3.connect(path)
    conn.executescript(v4)
    conn.execute("PRAGMA user_version = 4")
    conn.commit()
    db.migrate(conn)
    names = [r[0] for r in conn.execute("SELECT name FROM sqlite_master")]
    assert "users" in names
    assert conn.execute("PRAGMA user_version").fetchone()[0] == db.SCHEMA_VERSION


# Command line


@pytest.fixture
def cli(monkeypatch, passphrase):
    monkeypatch.setenv("ISDI_PASSPHRASE", passphrase)
    saved = audit.operator()
    yield lambda *a, **kw: CliRunner().invoke(cli_mod.cli, list(a), **kw)
    audit.set_operator(saved)


def test_cli_user_add_list_disable_enable(app, cli):
    name = f"u{uuid.uuid4().hex[:8]}"
    res = cli(
        "user",
        "add",
        name,
        "--name",
        "Pat Paralegal",
        input=f"short\nshort\n{PASSWORD}\n{PASSWORD}\n",
    )
    assert res.exit_code == 0, res.output
    assert "at least 12" in res.output and f"Created account {name}" in res.output
    with app.app_context():
        created = [(a, d) for a, _, d in _actions(app) if a == "user_created"]
    assert ("user_created", {"username": name}) in created

    res = cli("user", "list")
    line = next(x for x in res.output.splitlines() if x.startswith(name))
    assert "Pat Paralegal" in line and "active" in line and "never" in line

    assert cli("user", "disable", name).exit_code == 0
    assert "disabled" in next(
        x for x in cli("user", "list").output.splitlines() if x.startswith(name)
    )
    assert cli("user", "enable", name).exit_code == 0


def test_cli_user_add_asks_again_for_a_bad_or_taken_username(app, cli):
    name = f"u{uuid.uuid4().hex[:8]}"
    res = cli(
        "user",
        "add",
        input=f"Bad Name\n{TEST_USERNAME}\n{name}\n\nPat P\n{PASSWORD}\n{PASSWORD}\n",
    )
    assert res.exit_code == 0, res.output
    assert "A username is" in res.output and "already an account" in res.output
    assert res.output.count("Full name") == 2


def test_cli_locked_account_is_shown_and_reset_password_unlocks(app, cli, account):
    with app.app_context():
        for _ in range(users.MAX_FAILED):
            users.authenticate(account, "wrong password!")
    line = next(
        x for x in cli("user", "list").output.splitlines() if x.startswith(account)
    )
    assert "locked" in line
    new = "the replacement password"
    res = cli("user", "reset-password", account, input=f"{new}\n{new}\n")
    assert res.exit_code == 0, res.output
    with app.app_context():
        user, outcome = users.authenticate(account, new)
    assert outcome == "ok"


def test_cli_user_commands_on_unknown_accounts(cli):
    for args in (
        ["user", "disable", "nobody-here"],
        ["user", "enable", "nobody-here"],
        ["user", "reset-password", "nobody-here"],
    ):
        res = cli(*args)
        assert res.exit_code == 1 and "no account 'nobody-here'" in res.output


def test_cli_user_list_with_no_accounts(cli, fresh_log):  # noqa: F811
    res = cli("user", "list")
    assert "No accounts yet" in res.output


def test_run_creates_the_first_account(run_cli, fresh_log):  # noqa: F811
    output, _ = run_cli(input=f"first\nFirst Person\n{PASSWORD}\n{PASSWORD}\n")
    assert "Created account first for First Person" in output
    assert users.by_username("first")["name"] == "First Person"
    created = [e for e in audit.entries() if e["action"] == "user_created"]
    assert created[0]["operator"] == "isdi run (first account)"


def test_login_page_says_when_there_are_no_accounts(app, fresh_log):  # noqa: F811
    page = app.test_client(signed_in=False).get("/login")
    assert b"There are no accounts yet" in page.data


def test_check_password_reports_wrong_hashes(app):
    stored = users.hash_password(TEST_PASSWORD)
    assert users._password_matches(TEST_PASSWORD, stored)
    assert not users._password_matches(TEST_PASSWORD + "x", stored)
    assert json.dumps(stored).count("$") == 5
