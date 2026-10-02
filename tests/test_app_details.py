"""App detail pages: what the phone's dump said about an app is saved with
the scan (the dump itself is deleted), and one phone's details are never
shown for another."""

import re
import subprocess
from pathlib import Path

import pytest

import isdi.scanner as scanner
from isdi.config import get_config
from isdi.scanner import db, parse_dump

FIXTURE = Path(__file__).parent / "fixtures" / "android_dump.txt"


def _details(tmp_path, text=None):
    """Details as a scan would save them, from the fixture dump."""
    dumpf = tmp_path / "dump.txt"
    dumpf.write_text(text or FIXTURE.read_text())
    return {
        "com.example.spy": parse_dump.AndroidDump(str(dumpf)).info("com.example.spy")
    }


def _store_scan(app, serial_hmac, details):
    with app.app_context():
        scanid = db.create_scan(
            {
                "clientid": "20260101_001",
                "serial": serial_hmac,
                "device": "android",
                "device_model": "m",
                "device_version": "1",
                "device_manufacturer": "x",
                "last_full_charge": "",
                "device_primary_user": "o",
                "is_rooted": False,
                "rooted_reasons": "[]",
            }
        )
        db.create_mult_appinfo(
            [(scanid, appid, "[]", "", "<new>") for appid in details], details=details
        )
    return scanid


@pytest.fixture
def no_phone(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError(f"tried to talk to a phone: {a!r}")

    monkeypatch.setattr(subprocess, "Popen", refuse)
    monkeypatch.setattr(subprocess, "run", refuse)


def test_saved_scan_details_come_from_the_database(app, client, no_phone, tmp_path):
    serial = get_config().hmac_serial("SAVED-PHONE-1")
    _store_scan(app, serial, _details(tmp_path))
    r = client.get(
        "/details/app/test",
        query_string={"appId": "com.example.spy", "serial": serial, "from_dump": "1"},
    )
    assert r.status_code == 200
    html = r.get_data(as_text=True)
    assert "10234" in html and "2.1" in html  # userId and versionName from the dump


def test_live_details_use_the_latest_scan_of_that_phone(
    app, client, no_phone, tmp_path
):
    _store_scan(app, get_config().hmac_serial("LIVE-PHONE-1"), _details(tmp_path))
    r = client.get(
        "/details/app/test",
        query_string={"appId": "com.example.spy", "serial": "LIVE-PHONE-1"},
    )
    assert r.status_code == 200 and "10234" in r.get_data(as_text=True)


def test_saved_scan_details_require_a_stored_serial(client, no_phone):
    r = client.get(
        "/details/app/test",
        query_string={
            "appId": "com.example.spy",
            "serial": "RAWSERIAL",
            "from_dump": "1",
        },
    )
    assert r.status_code == 400


def test_saved_scan_links_mark_from_dump(app, client, no_phone):
    from isdi.scanner import db

    serial = get_config().hmac_serial("SAVED-PHONE-2")
    with client.session_transaction() as s:
        s["clientid"] = "20260101_001"
    with app.app_context():
        scanid = db.create_scan(
            {
                "clientid": "20260101_001",
                "serial": serial,
                "device": "test",
                "device_model": "m",
                "device_version": "1",
                "device_manufacturer": "x",
                "last_full_charge": "",
                "device_primary_user": "o",
                "is_rooted": False,
                "rooted_reasons": "[]",
            }
        )
        db.create_mult_appinfo([(scanid, "com.example.spy", "[]", "", "<new>")])
    r = client.get(
        "/scan",
        query_string={
            "device": "test",
            "device_owner": "o",
            "devid": serial,
            "from_dump": "1",
        },
    )
    details_links = re.findall(r'href="(/details/app/[^"]*)"', r.get_data(as_text=True))
    assert details_links and all("from_dump=1" in link for link in details_links)


def test_one_phones_details_are_not_shown_for_another(app, tmp_path):
    sc = scanner.AndroidScanner()
    a, b = get_config().hmac_serial("PHONE-A"), get_config().hmac_serial("PHONE-B")
    _store_scan(app, a, _details(tmp_path))
    other = FIXTURE.read_text().replace("versionName=2.1", "versionName=9.9")
    _store_scan(app, b, _details(tmp_path, other))

    with app.app_context():
        _, info_a = sc.app_details(a, "com.example.spy", stored=True)
        _, info_b = sc.app_details(b, "com.example.spy", stored=True)
    assert info_a["versionName"] == "2.1"
    assert info_b["versionName"] == "9.9"


def test_never_scanned_phone_gives_no_device_info(app, no_phone):
    sc = scanner.AndroidScanner()
    with app.app_context():
        _, info = sc.app_details(
            get_config().hmac_serial("NEVER-SCANNED"), "x", stored=True
        )
    assert info == {}
