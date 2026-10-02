"""App detail pages: saved scans read their stored dump, and a cached dump
from one phone is never shown for another."""

import re
import shutil
import subprocess
from pathlib import Path

import pytest

import isdi.scanner as scanner
from isdi.config import get_config

FIXTURE = Path(__file__).parent / "fixtures" / "android_dump.txt"


def _store_dump(serial_hmac, source=FIXTURE):
    """Put a dump where a past scan of this phone would have left it."""
    dumpf = Path(get_config().DUMP_DIR) / f"{serial_hmac}_android.txt"
    shutil.copy(source, dumpf)
    dumpf.with_suffix(".json").unlink(missing_ok=True)
    return dumpf


@pytest.fixture
def no_phone(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError(f"tried to talk to a phone: {a!r}")

    monkeypatch.setattr(subprocess, "Popen", refuse)
    monkeypatch.setattr(subprocess, "run", refuse)


def test_saved_scan_details_read_stored_dump(client, no_phone):
    serial = get_config().hmac_serial("SAVED-PHONE-1")
    _store_dump(serial)
    r = client.get(
        "/details/app/test",
        query_string={"appId": "com.example.spy", "serial": serial, "from_dump": "1"},
    )
    assert r.status_code == 200
    html = r.get_data(as_text=True)
    assert "10234" in html and "2.1" in html  # userId and versionName from the dump


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


def test_cached_dump_of_another_phone_is_not_reused(tmp_path):
    sc = scanner.AndroidScanner()
    a, b = get_config().hmac_serial("PHONE-A"), get_config().hmac_serial("PHONE-B")
    _store_dump(a)
    other = tmp_path / "b.txt"
    other.write_text(FIXTURE.read_text().replace("versionName=2.1", "versionName=9.9"))
    _store_dump(b, other)

    _, info_a = sc.app_details(a, "com.example.spy", stored=True)
    _, info_b = sc.app_details(b, "com.example.spy", stored=True)
    assert info_a["versionName"] == "2.1"
    assert info_b["versionName"] == "9.9"


def test_missing_stored_dump_gives_no_device_info(no_phone):
    sc = scanner.AndroidScanner()
    _, info = sc.app_details(
        get_config().hmac_serial("NEVER-SCANNED"), "x", stored=True
    )
    assert info == {}
