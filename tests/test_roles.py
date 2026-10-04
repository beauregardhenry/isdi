"""Roles and access to client records: staff open only the clients they
started, supervisors open every client, and scans are changed only in
their own client's session."""

import sqlite3
import uuid

import pytest
from click.testing import CliRunner

from isdi import audit, users
from isdi import cli as cli_mod
from isdi.scanner import db
from tests.test_accounts import PASSWORD, _sign_in
from tests.test_consult import _valid_form_data
from tests.test_data_protection import _live_scan, phone  # noqa: F401
from tests.test_scanner_pipeline import SERIAL


def _account(app, role):
    username = f"u{uuid.uuid4().hex[:10]}"
    with app.app_context():
        users.create(username, f"Person {username}", PASSWORD, role=role)
    c = app.test_client(signed_in=False)
    assert _sign_in(c, username).status_code == 302
    return username, c


def _start_client_with_notes(c):
    """Open the home page (which starts a new client) and save notes."""
    c.get("/")
    with c.session_transaction() as s:
        clientid = s["clientid"]
    assert c.post("/form/", data=_valid_form_data()).status_code == 200
    return clientid


def _note_pk(app, clientid):
    with app.app_context():
        return db.query_db(
            "SELECT id FROM clients_notes WHERE clientid=?", (clientid,), one=True
        )["id"]


@pytest.fixture
def two_staff(app, no_csrf):
    alice, a = _account(app, users.STAFF)
    bob, b = _account(app, users.STAFF)
    return (alice, a, _start_client_with_notes(a)), (
        bob,
        b,
        _start_client_with_notes(b),
    )


def test_staff_list_only_the_clients_they_started(app, two_staff):
    (_, a, mine), (_, _, theirs) = two_staff
    page = a.get("/form/edit/").data.decode()
    assert mine in page and theirs not in page


def test_staff_cannot_open_or_save_another_clients_notes(app, two_staff):
    (alice, a, mine), (_, b, theirs) = two_staff
    r = a.post("/form/edit/", data={"clientnote": _note_pk(app, theirs)})
    assert r.status_code == 403
    assert (
        a.post("/form/edit/", data={"clientnote": _note_pk(app, mine)}).status_code
        == 200
    )

    # A form opened before is refused too, if the session points elsewhere.
    with a.session_transaction() as s:
        s["form_edit_pk"] = _note_pk(app, theirs)
    r = a.post("/form/edit/", data=_valid_form_data(general_notes="overwrite"))
    assert r.status_code == 403
    with app.app_context():
        refusals = [e for e in audit.entries(theirs) if e["action"] == "access_refused"]
    assert len(refusals) == 2
    assert all(e["operator"] == f"Person {alice} ({alice})" for e in refusals)


def test_supervisors_open_every_client(app, two_staff):
    (_, _, mine), (_, _, theirs) = two_staff
    _, sup = _account(app, users.SUPERVISOR)
    page = sup.get("/form/edit/").data.decode()
    assert mine in page and theirs in page
    r = sup.post("/form/edit/", data={"clientnote": _note_pk(app, theirs)})
    assert r.status_code == 200


def test_new_client_ids_are_never_shared(app, no_csrf):
    """Before notes are saved, two people starting clients must still get
    different ids (scans of one must not show up for the other)."""
    _, a = _account(app, users.STAFF)
    _, b = _account(app, users.STAFF)
    a.get("/")
    b.get("/")
    ids = []
    for c in (a, b):
        with c.session_transaction() as s:
            ids.append(s["clientid"])
    assert ids[0] != ids[1]


@pytest.mark.parametrize(
    "path, data",
    [
        ("/savescan/{sid}", {"notes": "changed by someone else"}),
        ("/saveapps/{sid}", {"com.example": "remark"}),
        ("/delete/app/{sid}", {"serial": SERIAL, "appid": "com.whatsapp"}),
    ],
)
def test_scans_are_changed_only_in_their_clients_session(
    app, no_csrf, phone, client_of, path, data  # noqa: F811
):
    clientid, result, _ = _live_scan(app, "Owner")
    sid = result["scanid"]
    other = client_of(f"other_{uuid.uuid4().hex[:6]}")
    r = other.post(path.format(sid=sid), data=data)
    assert r.status_code == 404
    with app.app_context():
        scan = db.get_scan_res_from_db(sid)
        actions = [e["action"] for e in audit.entries(clientid)]
    assert scan["note"] is None
    assert "access_refused" in actions
    assert not any(a.startswith("app_uninstall") for a in actions)


def test_deleting_a_device_keeps_other_clients_scans_of_it(
    app, no_csrf, phone, client_of  # noqa: F811
):
    from isdi.config import get_config

    first, r1, _ = _live_scan(app, "Owner")
    second, r2, _ = _live_scan(app, "Owner")
    serial = get_config().hmac_serial(SERIAL)
    client_of(first).post("/delete_device", data={"serial": serial})
    with app.app_context():
        assert db.get_scan_res_from_db(r1["scanid"]) is None
        assert db.get_scan_res_from_db(r2["scanid"]) is not None


@pytest.fixture
def cli(monkeypatch, passphrase):
    monkeypatch.setenv("ISDI_PASSPHRASE", passphrase)
    saved = audit.operator()
    yield lambda *a, **kw: CliRunner().invoke(cli_mod.cli, list(a), **kw)
    audit.set_operator(saved)


def test_cli_roles(app, cli):
    name = f"u{uuid.uuid4().hex[:8]}"
    res = cli(
        "user",
        "add",
        name,
        "--name",
        "Sam Sup",
        "--supervisor",
        input=f"{PASSWORD}\n{PASSWORD}\n",
    )
    assert res.exit_code == 0 and f"Created supervisor account {name}" in res.output
    line = next(
        x for x in cli("user", "list").output.splitlines() if x.startswith(name)
    )
    assert "supervisor" in line

    assert cli("user", "role", name, "staff").exit_code == 0
    with app.app_context():
        assert users.by_username(name)["role"] == "staff"
        change = [e for e in audit.entries() if e["action"] == "user_role_changed"][-1]
    assert change["details"] == {"username": name, "role": ["supervisor", "staff"]}

    res = cli("user", "role", name, "admin")
    assert res.exit_code == 2  # not a choice
    with app.app_context(), pytest.raises(users.AccountError, match="A role is"):
        users.create("x" + name, "N", PASSWORD, role="admin")


def test_accounts_from_before_roles_become_supervisors(tmp_path):
    """They could open every client before: the upgrade keeps that."""
    v5 = db.SCHEMA_SQL.replace(",\n  role TEXT NOT NULL DEFAULT 'staff'", "")
    v5 = v5[: v5.index("-- Which clients a staff account")]
    path = tmp_path / "v5.db"
    conn = sqlite3.connect(path)
    conn.executescript(v5)
    conn.execute(
        "INSERT INTO users (username, password_hash, created) VALUES ('old', 'h', 't')"
    )
    conn.execute("PRAGMA user_version = 5")
    conn.commit()
    db.migrate(conn)
    db.migrate(conn)
    assert conn.execute("SELECT role FROM users").fetchone()[0] == "supervisor"
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master")}
    assert "client_access" in tables
