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
                "device_primary_user": "Nickname-7f",
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


def _row(app, scanid, appid="com.example.spy"):
    with app.app_context():
        return db.app_row_ids(scanid)[appid]


def test_details_come_from_the_database(app, client, no_phone, tmp_path):
    scanid = _store_scan(
        app, get_config().hmac_serial("SAVED-PHONE-1"), _details(tmp_path)
    )
    r = client.get(f"/scan/{scanid}/app/{_row(app, scanid)}")
    assert r.status_code == 200
    html = r.get_data(as_text=True)
    assert "10234" in html and "2.1" in html  # userId and versionName from the dump


def test_details_of_another_clients_scan_are_refused(app, no_phone, tmp_path):
    scanid = _store_scan(
        app, get_config().hmac_serial("SAVED-PHONE-3"), _details(tmp_path)
    )
    other = app.test_client()
    with other.session_transaction() as s:
        s["clientid"] = "20260101_999"
    assert other.get(f"/scan/{scanid}/app/{_row(app, scanid)}").status_code == 404
    assert other.get(f"/scan/saved/{scanid}").status_code == 404


@pytest.mark.parametrize("path", ["/scan/{s}/app/999999", "/scan/999999/app/1"])
def test_unknown_scan_or_app_is_404(app, client, no_phone, tmp_path, path):
    scanid = _store_scan(
        app, get_config().hmac_serial("SAVED-PHONE-4"), _details(tmp_path)
    )
    assert client.get(path.format(s=scanid)).status_code == 404


def _links(html):
    return re.findall(r'href="([^"]*)"', html)


def test_links_carry_no_serial_nickname_or_app_id(app, client, tmp_path):
    """Browser history keeps every URL visited: links must hold only ids."""
    serial = get_config().hmac_serial("SAVED-PHONE-2")
    scanid = _store_scan(app, serial, _details(tmp_path))
    home = client.get("/").get_data(as_text=True)
    assert f"/scan/saved/{scanid}" in _links(home)

    page = client.get(f"/scan/saved/{scanid}").get_data(as_text=True)
    details = [l for l in _links(page) if "/app/" in l]
    assert details == [f"/scan/{scanid}/app/{_row(app, scanid)}"] * len(details)
    assert details
    internal = [l for l in _links(home) + _links(page) if l.startswith("/")]
    for link in internal:
        for secret in (serial, "Nickname-7f", "com.example.spy", "serial=", "devid="):
            assert secret not in link, link


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


def test_live_scan_results_link_by_id_only(app, client, no_csrf):
    r = client.post(
        "/scan",
        data={"device": "test", "device_owner": "Nickname-9c", "devid": "testdevice1"},
    )
    assert r.status_code == 200
    links = [l for l in _links(r.get_data(as_text=True)) if l.startswith("/")]
    details = [l for l in links if "/app/" in l]
    assert details and all(re.fullmatch(r"/scan/\d+/app/\d+", l) for l in details)
    assert client.get(details[0]).status_code == 200
    for link in links:
        assert "testdevice1" not in link and "Nickname-9c" not in link


def test_details_come_from_the_scan_in_the_url(app, client, no_phone, tmp_path):
    """The same phone scanned again (for another client, say) must not
    change what an earlier scan's details page shows."""
    serial = get_config().hmac_serial("SAVED-PHONE-4")
    first = _store_scan(app, serial, _details(tmp_path))
    later_details = _details(
        tmp_path, FIXTURE.read_text().replace("versionName=2.1", "versionName=9.9")
    )
    assert later_details["com.example.spy"] != _details(tmp_path)["com.example.spy"]
    _store_scan(app, serial, later_details)

    html = client.get(f"/scan/{first}/app/{_row(app, first)}").get_data(as_text=True)
    assert "2.1" in html and "9.9" not in html
