"""The audit log: what is recorded, and that changes to it are detected."""

import uuid
from pathlib import Path

import pytest
from click.testing import CliRunner

from isdi import audit, crypto
from isdi.scanner import db
from tests.test_consult import _valid_form_data
from tests.test_data_protection import _database_bytes, _live_scan, phone  # noqa: F401
from tests.test_scanner_pipeline import SERIAL, STALKER


@pytest.fixture
def fresh_log(app, tmp_path, monkeypatch):
    """An empty database of its own, so tampering does not touch the
    suite's shared log."""
    monkeypatch.setattr(db, "DATABASE", str(tmp_path / "audit.db"))
    with app.app_context():
        yield db.get_db()


def _three_entries():
    for i in range(3):
        audit.record("test_action", clientid="c1", details={"n": i})


def test_entries_chain_and_verify(fresh_log):
    _three_entries()
    rows = audit.entries()
    assert [r["id"] for r in rows] == [1, 2, 3]
    assert rows[0]["prev"] == audit.GENESIS
    assert rows[1]["prev"] == rows[0]["mac"] and rows[2]["prev"] == rows[1]["mac"]
    assert rows[0]["operator"] == "Test Operator"
    assert rows[2]["details"] == {"n": 2}
    assert rows[0]["time"].endswith("+00:00")  # UTC
    assert audit.verify() == {"ok": True, "entries": 3, "erased": 0, "problem": None}


@pytest.mark.parametrize(
    "tamper, problem",
    [
        ("UPDATE audit_log SET action='other' WHERE id=2", "entry 2 was altered"),
        ("UPDATE audit_log SET time='2020-01-01' WHERE id=1", "entry 1 was altered"),
        ("DELETE FROM audit_log WHERE id=2", "entry 2 is missing"),
        (
            "UPDATE audit_log SET prev=(SELECT mac FROM audit_log WHERE id=1) WHERE id=3",
            "entry 3 does not follow entry 2",
        ),
    ],
)
def test_tampering_is_detected(fresh_log, tamper, problem):
    _three_entries()
    fresh_log.execute(tamper)
    fresh_log.commit()
    result = audit.verify()
    assert not result["ok"] and result["problem"] == problem


def test_altered_details_are_detected(fresh_log):
    _three_entries()
    fresh_log.execute(
        "UPDATE audit_log SET details=? WHERE id=2",
        (crypto.encrypt("details", {"n": 99}),),
    )
    fresh_log.commit()
    assert audit.verify()["problem"] == "the details of entry 2 were altered"


def test_entry_cannot_be_forged_without_the_key(fresh_log):
    """Someone with the database but not the passphrase cannot compute a
    valid MAC for an added entry."""
    import hashlib

    _three_entries()
    last = fresh_log.execute("SELECT mac FROM audit_log WHERE id=3").fetchone()["mac"]
    forged = hashlib.sha256(b"guess").hexdigest()
    fresh_log.execute(
        "INSERT INTO audit_log (id, time, action, details_mac, prev, mac) "
        "VALUES (4, '2026-01-01T00:00:00+00:00', 'forged', ?, ?, ?)",
        (forged, last, forged),
    )
    fresh_log.commit()
    assert audit.verify()["problem"] == "entry 4 was altered"


def test_erased_details_keep_the_chain_valid(fresh_log):
    _three_entries()
    audit.record("other_client", clientid="c2", details={"keep": True})
    assert audit.erase_client_details("c1") == 3
    rows = audit.entries()
    assert [r["details"] for r in rows] == [None, None, None, {"keep": True}]
    assert audit.verify() == {"ok": True, "entries": 4, "erased": 3, "problem": None}


def test_live_scan_is_recorded_with_its_provenance(app, phone):  # noqa: F811
    from isdi.scanner import blocklist

    clientid, result, _ = _live_scan(app, "Owner")
    with app.app_context():
        [entry] = [e for e in audit.entries(clientid) if e["action"] == "scan_saved"]
        scan = db.get_scan_res_from_db(result["scanid"])
    assert entry["scanid"] == result["scanid"]
    assert entry["operator"] == "Test Operator" and scan["operator"] == "Test Operator"
    d = entry["details"]
    assert d["model"] == "Pixel 8" and d["nickname"] == "Owner"
    assert d["blocklist_sha256"] == blocklist.BLOCKLIST_SHA256
    assert d["isdi_version"]
    assert d["apps"] == len(result["apps"])
    assert "Test Operator".encode() not in _database_bytes()


def test_note_edits_keep_old_and_new_values(app, no_csrf):
    from isdi.web.model import Client

    c = app.test_client()
    clientid = f"au_{uuid.uuid4().hex[:8]}"
    with c.session_transaction() as s:
        s["clientid"] = clientid
    c.post("/form/", data=_valid_form_data(general_notes="first version"))
    with app.app_context():
        pk = Client.query.filter_by(clientid=clientid).first().id
    c.post("/form/edit/", data={"clientnote": pk})
    c.post("/form/edit/", data=_valid_form_data(general_notes="second version"))

    with app.app_context():
        actions = {e["action"]: e for e in audit.entries(clientid)}
    assert actions["notes_created"]["details"]["general_notes"] == "first version"
    assert actions["notes_edited"]["details"]["changes"] == {
        "general_notes": ["first version", "second version"]
    }


def test_scan_note_changes_are_recorded(app, no_csrf, phone):  # noqa: F811
    clientid, result, _ = _live_scan(app, "Owner")
    c = app.test_client()
    sid = result["scanid"]
    c.post(f"/savescan/{sid}", data={"notes": "photographed the app list"})
    c.post(f"/savescan/{sid}", data={"notes": "photographed the app list"})  # no change
    with app.app_context():
        notes = [e for e in audit.entries(clientid) if e["action"] == "scan_note_saved"]
    assert [n["details"]["note"] for n in notes] == [
        [None, "photographed the app list"]
    ]


def test_uninstall_attempts_are_recorded(app, no_csrf, phone):  # noqa: F811
    clientid, result, _ = _live_scan(app, "Owner")
    c = app.test_client()
    sid = result["scanid"]
    # The fake adb uninstalls com.whatsapp and refuses anything else.
    c.post(f"/delete/app/{sid}", data={"serial": SERIAL, "appid": "com.whatsapp"})
    c.post(f"/delete/app/{sid}", data={"serial": SERIAL, "appid": STALKER})
    with app.app_context():
        acts = [
            (e["action"], e["details"]["appid"])
            for e in audit.entries(clientid)
            if e["action"].startswith("app_uninstall")
        ]
    assert acts == [
        ("app_uninstalled", "com.whatsapp"),
        ("app_uninstall_failed", STALKER),
    ]


def test_non_numeric_scan_ids_are_not_routed(client, no_csrf):
    assert client.post("/savescan/abc", data={"notes": "x"}).status_code == 404


def test_deleting_a_device_blanks_its_entries_and_is_recorded(
    app, client, no_csrf, phone  # noqa: F811
):
    from isdi.config import get_config

    clientid, result, _ = _live_scan(app, "Owner")
    serial_hmac = get_config().hmac_serial(SERIAL)
    client.post("/delete_device", data={"serial": serial_hmac})
    with app.app_context():
        mine = audit.entries(clientid)
        deleted = [e for e in audit.entries() if e["action"] == "device_data_deleted"]
        assert audit.verify()["ok"]
    assert all(e["details"] is None for e in mine if e["scanid"] == result["scanid"])
    assert result["scanid"] in deleted[-1]["details"]["scans"]


def test_export_includes_the_trail_and_erase_is_recorded(app, phone):  # noqa: F811
    clientid, result, _ = _live_scan(app, "Owner")
    with app.app_context():
        data = db.export_client(clientid)
        assert [e["action"] for e in data["audit_log"]] == ["scan_saved"]
        assert data["audit_head"]["id"] >= data["audit_log"][-1]["id"]
        counts = db.erase_client(clientid)
        assert counts["audit_details"] == 1
        assert audit.entries(clientid)[0]["details"] is None
        assert audit.verify()["ok"]


@pytest.fixture
def cli(monkeypatch, passphrase):
    from isdi import cli as cli_mod

    monkeypatch.setenv("ISDI_PASSPHRASE", passphrase)
    saved = audit.operator()
    yield lambda *a, **kw: CliRunner().invoke(cli_mod.cli, list(a), **kw)
    audit.set_operator(saved)


def test_cli_audit_verify(app, cli):
    res = cli("audit", "verify")
    assert res.exit_code == 0, res.output
    assert "Audit log intact" in res.output


def test_cli_audit_verify_reports_tampering(app, cli, fresh_log):
    _three_entries()
    fresh_log.execute("UPDATE audit_log SET action='x' WHERE id=1")
    fresh_log.commit()
    res = cli("audit", "verify")
    assert res.exit_code == 1 and "entry 1 was altered" in res.output


def test_cli_asks_for_the_operator_when_not_given(app, cli, monkeypatch):
    monkeypatch.delenv("ISDI_OPERATOR")
    res = cli("audit", "verify", input="\nJane Advocate\n")
    assert res.exit_code == 0, res.output
    assert res.output.count("Your name") == 2  # an empty answer is asked again
    assert audit.operator() == "Jane Advocate"


def test_uninstall_warns_about_evidence_and_safety(app):
    js = (Path(app.static_folder) / "myjscript.js").read_text()
    assert "Removing an app can destroy evidence" in js
    assert "alert the person who installed it" in js
