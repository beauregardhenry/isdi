"""iPhone supervision and configuration profiles, and the plain-language
summary of a scan for the client."""

import json
import sqlite3

import pytest

from isdi import audit, client_summary
from isdi.config import get_config
from isdi.scanner import db, ios_management as im

PROFILES = {
    "OrderedIdentifiers": ["com.corp.mdm", "missing.id"],
    "ProfileMetadata": {
        "com.vpn": {"PayloadDisplayName": "VPN"},
        "com.corp.mdm": {
            "PayloadDisplayName": "Device Management",
            "PayloadOrganization": "Corp <b>",
            "PayloadDescription": "Manages this phone",
            "PayloadRemovalDisallowed": True,
        },
        "odd": "not a dict",
    },
    "Status": "Acknowledged",
}


def test_profiles_in_order_then_the_rest():
    profiles = im.profiles_from(PROFILES)
    assert [p["identifier"] for p in profiles] == ["com.corp.mdm", "com.vpn", "odd"]
    assert profiles[0] == {
        "identifier": "com.corp.mdm",
        "name": "Device Management",
        "organization": "Corp <b>",
        "description": "Manages this phone",
        "removal_disallowed": True,
    }
    assert profiles[2]["name"] == "odd"  # no metadata: the identifier


@pytest.mark.parametrize(
    "response", [None, "x", {}, {"ProfileMetadata": []}, {"ProfileMetadata": {}}]
)
def test_no_profiles(response):
    assert im.profiles_from(response) == []


@pytest.mark.parametrize(
    "cloud, expected",
    [
        (None, {"supervised": None, "organization": ""}),
        (
            {"IsSupervised": True, "OrganizationName": " Org "},
            {"supervised": True, "organization": "Org"},
        ),
        ({"IsSupervised": False}, {"supervised": False, "organization": ""}),
        ({"IsSupervised": "yes"}, {"supervised": None, "organization": ""}),
    ],
)
def test_supervision(cloud, expected):
    assert im.supervision_from(cloud) == expected


def test_check_reads_the_phone(monkeypatch):
    async def read(serial):
        assert serial == "00008030-TEST"
        return PROFILES, {"IsSupervised": True, "OrganizationName": "Org"}

    monkeypatch.setattr(im, "_read", read)
    info = im.check("00008030-TEST")
    assert info["checked"] and info["supervised"] and info["error"] is None
    assert len(info["profiles"]) == 3
    assert im.is_managed(info)


def test_a_phone_that_cannot_be_read_is_not_reported_unmanaged(monkeypatch, caplog):
    async def read(serial):
        raise ConnectionError("locked")

    monkeypatch.setattr(im, "_read", read)
    info = im.check("00008030-TEST")
    assert info == {
        "checked": False,
        "supervised": None,
        "organization": "",
        "profiles": [],
        "error": "ConnectionError",
    }
    assert not im.is_managed(info)
    assert "Could not check" in im.summary_html(info)
    assert "locked" not in caplog.text  # only the error's type is logged


def test_without_usbmuxd_the_check_fails_cleanly():
    """The real pymobiledevice3 path, with no phone attached."""
    assert im.check("00008030-NOPHONE")["checked"] is False


def test_summary_line_is_escaped():
    info = {
        "checked": True,
        "supervised": True,
        "organization": "<script>",
        "profiles": im.profiles_from(PROFILES),
    }
    html = im.summary_html(info)
    assert "<script>" not in html and "&lt;script&gt;" in html
    assert "Corp &lt;b&gt;" in html and "3 configuration profiles" in html
    clean = {"checked": True, "supervised": False, "profiles": []}
    assert im.summary_html(clean) == "Not supervised; no configuration profiles."
    assert im.summary_html(None) == ""


def test_the_base_scanner_does_not_check():
    from isdi.scanner import AndroidScanner

    assert AndroidScanner().device_management("x") is None


def test_ios_scanner_runs_the_check(monkeypatch):
    from isdi.scanner import IosScanner

    monkeypatch.setattr(im, "check", lambda serial: {"checked": True, "s": serial})
    assert IosScanner().device_management("abc") == {"checked": True, "s": "abc"}


def test_databases_from_before_the_check_gain_the_column(tmp_path):
    v6 = db.SCHEMA_SQL.replace(",\n  device_management TEXT", "")
    assert v6 != db.SCHEMA_SQL
    conn = sqlite3.connect(tmp_path / "v6.db")
    conn.executescript(v6)
    conn.execute("PRAGMA user_version = 6")
    conn.commit()
    db.migrate(conn)
    cols = {r[1] for r in conn.execute("PRAGMA table_info(scan_res)")}
    assert "device_management" in cols
    assert conn.execute("PRAGMA user_version").fetchone()[0] == db.SCHEMA_VERSION


# ---------------------------------------------------------------- summary

MANAGED = {
    "checked": True,
    "supervised": True,
    "organization": "Org",
    "profiles": [{"name": "MDM", "organization": "Org"}],
}


def _scan(**kw):
    scan = {
        "device": "ios",
        "device_manufacturer": "Apple",
        "device_model": "iPhone 15",
        "is_rooted": False,
        "device_management": json.dumps(MANAGED),
    }
    scan.update(kw)
    return scan


APPS = {
    "com.spy": {"title": "Spy", "flags": ["stalkerware", "offstore-app"]},
    "com.life360": {"title": "Life360", "flags": ["dual-use"]},
    "com.pw": {"title": "", "flags": ["accessibility"]},
    "com.plain": {"title": "Plain", "flags": []},
}


def test_summary_findings():
    s = client_summary.build(_scan(is_rooted=True), APPS)
    assert s["phone"] == "Apple iPhone 15"
    assert "(4 in all)" in s["checked"][0] and "jailbreaking" in s["checked"][1]
    titles = [f["title"] for f in s["findings"]]
    assert titles == [
        "Apps known to be used for monitoring",
        "The phone's protections appear to have been removed",
        "The phone is managed",
        "Apps with powerful permissions",
        "Apps that can share location or activity",
    ]
    assert s["findings"][0]["items"] == ["Spy (com.spy)"]
    assert s["findings"][2]["items"] == ["The phone is supervised by Org.", "MDM (Org)"]
    assert s["findings"][3]["items"] == ["com.pw"]
    assert not s["management_unchecked"]


def test_summary_with_nothing_found():
    s = client_summary.build(
        _scan(device="android", device_manufacturer="<Unknown>", device_model=""),
        {"com.plain": {"title": "", "flags": []}},
    )
    assert s["findings"] == [] and s["phone"] == "the phone"
    assert "rooting" in s["checked"][1] and len(s["checked"]) == 2


@pytest.mark.parametrize("stored", [None, "not json", json.dumps({"checked": False})])
def test_summary_when_management_was_not_checked(stored):
    s = client_summary.build(_scan(device_management=stored), {})
    assert not any(f["title"] == "The phone is managed" for f in s["findings"])
    assert s["management_unchecked"] is (stored is not None and "checked" in stored)


def _store(app, clientid="20260101_001", management=MANAGED):
    with app.app_context():
        scanid = db.create_scan(
            {
                "clientid": clientid,
                "serial": get_config().hmac_serial("SUMMARY-PHONE"),
                "device": "ios",
                "device_model": "iPhone 15",
                "device_version": "18",
                "device_manufacturer": "Apple",
                "last_full_charge": "unknown",
                "device_primary_user": "Nick",
                "is_rooted": False,
                "rooted_reasons": "[]",
                "device_management": json.dumps(management),
            }
        )
        db.create_mult_appinfo(
            [(scanid, "com.spy", json.dumps(["stalkerware"]), "", "<new>")],
            details={},
        )
    return scanid


def test_summary_page(app, client):
    scanid = _store(app)
    page = client.get(f"/scan/{scanid}/client-summary").get_data(as_text=True)
    assert "<title>Phone check summary</title>" in page
    assert "com.spy" in page and "The phone is supervised by Org." in page
    assert 'data-action="print"' in page and "d-print-none" in page
    assert "spyware" not in page.lower().split("<body")[0]  # not in the head
    with app.app_context():
        viewed = [e for e in audit.entries() if e["action"] == "client_summary_viewed"]
    assert viewed[-1]["scanid"] == scanid

    saved = client.get(f"/scan/saved/{scanid}").get_data(as_text=True)
    assert f"/scan/{scanid}/client-summary" in saved
    assert "Supervised</span> by Org" in saved


def test_another_clients_summary_is_refused(app):
    scanid = _store(app)
    other = app.test_client()
    with other.session_transaction() as s:
        s["clientid"] = "20260101_999"
    assert other.get(f"/scan/{scanid}/client-summary").status_code == 404
    assert app.test_client().get(f"/scan/{scanid}/client-summary").status_code == 302
