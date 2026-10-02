"""End-to-end web flows against the stub TestScanner: scanning, viewing a
saved scan, uninstalling an app, saving notes."""

import time
import uuid

import pytest

import isdi.scanner as scanner
from isdi.config import get_config
from isdi.scanner import blocklist, db

# A real entry from app-flags.csv, so the flow exercises the shipped blocklist.
STALKER = next(
    r["appId"] for r in blocklist.APP_FLAGS.data if r["flag"] == "stalkerware"
)


@pytest.fixture
def fake_phone(monkeypatch):
    """The stub TestScanner reports a fixed app list and records uninstalls."""
    uninstalled = []
    monkeypatch.setattr(
        scanner.TestScanner,
        "get_apps",
        lambda self, s: ["org.example.calculator", STALKER],
    )
    monkeypatch.setattr(
        scanner.TestScanner,
        "uninstall",
        lambda self, serial, appid: uninstalled.append((serial, appid)) or True,
    )
    return uninstalled


@pytest.fixture
def session_client(app):
    c = app.test_client()
    with c.session_transaction() as s:
        s["clientid"] = f"flow_{uuid.uuid4().hex[:10]}"
    return c


def _run_scan(client):
    r = client.post(
        "/scan/start",
        data={"device": "test", "device_owner": "Sam", "devid": "testdevice1"},
    )
    assert r.status_code == 200, r.get_json()
    job = r.get_json()
    for _ in range(100):
        state = client.get(job["status_url"]).get_json()
        if state["status"] in ("done", "error"):
            break
        time.sleep(0.05)
    assert state["status"] == "done", state
    return job


def test_scan_job_end_to_end(no_csrf, fake_phone, session_client):
    job = _run_scan(session_client)
    r = session_client.get(job["result_url"])
    assert r.status_code == 200
    html = r.get_data(as_text=True)
    # Known stalkerware is listed first, highlighted, and flagged.
    assert html.index(STALKER) < html.index("org.example.calculator")
    assert "alert-primary" in html and "stalkerware" in html


def test_scan_result_not_visible_to_other_session(
    no_csrf, fake_phone, app, session_client
):
    job = _run_scan(session_client)
    other = app.test_client()
    with other.session_transaction() as s:
        s["clientid"] = "someone_else"
    r = other.get(job["result_url"])
    assert r.status_code == 302


def test_status_of_unknown_job(client):
    assert client.get("/scan/status/" + "0" * 32).status_code == 404


def test_finished_jobs_are_pruned_after_ttl(app):
    from isdi.web.view import scan as scan_view

    now = time.time()
    jobs = {
        "old_done": {"status": "done", "updated_at": now - scan_view._SCAN_JOB_TTL - 1},
        "old_running": {
            "status": "running",
            "updated_at": now - scan_view._SCAN_JOB_TTL - 1,
        },
        "new_done": {"status": "done", "updated_at": now},
    }
    with scan_view._SCAN_JOBS_LOCK:
        scan_view._SCAN_JOBS.update(jobs)
    scan_view._prune_scan_jobs()
    with scan_view._SCAN_JOBS_LOCK:
        left = {k for k in jobs if k in scan_view._SCAN_JOBS}
        for k in jobs:
            scan_view._SCAN_JOBS.pop(k, None)
    assert left == {"old_running", "new_done"}


def test_saved_scan_can_be_reopened(no_csrf, fake_phone, session_client):
    _run_scan(session_client)
    serial = get_config().hmac_serial("testdevice1")
    r = session_client.get(
        "/scan",
        query_string={
            "device": "test",
            "device_owner": "Sam",
            "devid": serial,
            "from_dump": "1",
        },
    )
    assert r.status_code == 200
    html = r.get_data(as_text=True)
    assert STALKER in html and "stalkerware" in html


def test_reopen_rejects_raw_serial(no_csrf, session_client):
    r = session_client.get(
        "/scan",
        query_string={
            "device": "test",
            "device_owner": "Sam",
            "devid": "x;id",
            "from_dump": "1",
        },
    )
    assert "Invalid device id" in r.get_data(as_text=True)


@pytest.fixture
def stored_scan(app):
    with app.app_context():
        scanid = db.create_scan(
            {
                "clientid": "20260101_001",
                "serial": get_config().hmac_serial("REALSERIAL1"),
                "device": "test",
                "device_model": "m",
                "device_version": "1",
                "device_manufacturer": "x",
                "last_full_charge": "unknown",
                "device_primary_user": "o",
                "is_rooted": False,
                "rooted_reasons": "[]",
            }
        )
        db.create_mult_appinfo([(scanid, "com.example.mdm", "[]", "", "<new>")])
    return scanid


def test_uninstall_requires_the_scanned_devices_serial(
    no_csrf, fake_phone, client, stored_scan
):
    r = client.post(
        f"/delete/app/{stored_scan}",
        data={"serial": "OTHERSERIAL", "appid": "com.example.mdm"},
    )
    assert r.status_code == 400
    assert fake_phone == []


def test_uninstall_uses_raw_serial_and_records_action(
    no_csrf, fake_phone, app, client, stored_scan
):
    r = client.post(
        f"/delete/app/{stored_scan}",
        data={
            "serial": "REALSERIAL1",
            "appid": "com.example.mdm",
            "remark": "client asked",
        },
    )
    assert r.status_code == 200
    assert fake_phone == [("REALSERIAL1", "com.example.mdm")]
    with app.app_context():
        (row,) = db.get_app_info_from_db(stored_scan)
    assert row["action_taken"] == "delete" and row["remark"] == "client asked"


def test_uninstall_unknown_scan(no_csrf, client):
    r = client.post("/delete/app/999999999", data={"serial": "S1", "appid": "com.x"})
    assert r.status_code == 404


def test_save_notes_writes_report(no_csrf, client, stored_scan):
    r = client.post(f"/savescan/{stored_scan}", data={"notes": "checked with client"})
    assert r.status_code == 200
