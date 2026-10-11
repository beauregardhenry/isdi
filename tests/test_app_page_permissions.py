"""The app details page shows what the phone reported about the app's
permissions, in words a client can follow, and keeps the store's list
apart from it."""

from pathlib import Path

import pytest

from isdi.config import get_config
from isdi.scanner import app_permissions, db, parse_dump

FIXTURE = Path(__file__).parent / "fixtures" / "android_dump.txt"

PERMISSION_LINES = """    lastUpdateTime=2026-09-01 12:00:00
    install permissions:
      android.permission.INTERNET: granted=true
      android.permission.RECEIVE_BOOT_COMPLETED: granted=true
    runtime permissions:
      android.permission.CAMERA: granted=true, flags=[ USER_SET ]
      android.permission.ACCESS_FINE_LOCATION: granted=false, flags=[ USER_SET ]
      android.permission.READ_SMS: granted=true, flags=[ USER_SET ]
      com.example.CUSTOM_<b>THING</b>: granted=true
"""


def _android_info(tmp_path):
    text = FIXTURE.read_text().replace(
        "    lastUpdateTime=2026-09-01 12:00:00\n", PERMISSION_LINES, 1
    )
    dumpf = tmp_path / "dump.txt"
    dumpf.write_text(text)
    return parse_dump.AndroidDump(str(dumpf)).info("com.example.spy")


IOS_INFO = {
    "App Version": "4.2",
    "permissions": [
        ["Camera", "Scan documents"],
        ["Location", "Permission granted by system"],
        ["Microphone", "undefined in InfoPlist.strings"],
    ],
}


def _store(app, device, appid, info):
    with app.app_context():
        scanid = db.create_scan(
            {
                "clientid": "20260101_001",
                "serial": get_config().hmac_serial(f"PERM-{device}"),
                "device": device,
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
            [(scanid, appid, "[]", "", "<new>")], details={appid: info}
        )
        row = db.app_row_ids(scanid)[appid]
    return f"/scan/{scanid}/app/{row}"


def test_android_permissions_parse_with_labels_and_state(tmp_path):
    rows = app_permissions.from_phone("android", _android_info(tmp_path))
    by_name = {r["name"]: r for r in rows}
    camera = by_name["android.permission.CAMERA"]
    assert camera["label"] == "Take pictures and videos"
    assert camera["granted"] is True and camera["sensitive"]
    assert camera["kind"] == "runtime"
    assert by_name["android.permission.ACCESS_FINE_LOCATION"]["granted"] is False
    assert by_name["android.permission.INTERNET"]["kind"] == "install"
    assert not by_name["android.permission.INTERNET"]["sensitive"]


def test_granted_sensitive_permissions_come_first(tmp_path):
    rows = app_permissions.from_phone("android", _android_info(tmp_path))
    flags = [(r["sensitive"], r["granted"]) for r in rows]
    first_other = next(i for i, f in enumerate(flags) if f != (True, True))
    assert first_other == 2  # camera and SMS
    assert all(f != (True, True) for f in flags[first_other:])


def test_ios_reasons_are_reworded():
    rows = app_permissions.from_phone("ios", IOS_INFO)
    assert [(r["name"], r["reason"]) for r in rows] == [
        ("Camera", "Scan documents"),
        ("Location", "Granted by the system"),
        ("Microphone", "No reason given in the app"),
    ]


def test_info_rows_leave_out_internal_fields(tmp_path):
    rows = dict(app_permissions.info_rows(_android_info(tmp_path)))
    assert rows["Version"] == "2.1"
    assert rows["Data usage"] == "3.00 MB; background data not allowed"
    assert "userId" not in rows and "runtime permissions" not in rows


@pytest.mark.parametrize("info", [None, "", [], {}])
def test_missing_details_give_nothing(info):
    assert app_permissions.from_phone("android", info) == []
    assert app_permissions.info_rows(info) == []


def test_android_page_lists_what_the_phone_granted(app, client, tmp_path):
    url = _store(app, "android", "com.example.spy", _android_info(tmp_path))
    html = client.get(url).get_data(as_text=True)
    assert "Permissions the phone reports" in html
    assert "Take pictures and videos" in html
    assert "Read your text messages" in html
    assert "app permissions recently" not in html
    assert 'class="table-warning"' in html
    # A permission name from the phone is escaped.
    assert "<b>THING</b>" not in html and "&lt;b&gt;THING" in html


def test_ios_page_shows_the_apps_reasons(app, client):
    url = _store(app, "ios", "com.example.ios", IOS_INFO)
    html = client.get(url).get_data(as_text=True)
    assert "The app&#39;s reason" in html or "The app's reason" in html
    assert "Scan documents" in html and "Granted by the system" in html
    assert "Granted</th>" not in html


def test_page_says_when_nothing_was_recorded(app, client):
    url = _store(app, "android", "com.example.empty", {"versionName": "1.0"})
    html = client.get(url).get_data(as_text=True)
    assert "The scan did not record this app&#39;s permissions." in html or (
        "The scan did not record this app's permissions." in html
    )
    assert "non_hf" not in html


def test_unknown_app_is_named_by_its_id_without_an_empty_description(app, client):
    url = _store(app, "android", "com.example.unlisted", {"versionName": "1.0"})
    html = client.get(url).get_data(as_text=True)
    assert "Information about com.example.unlisted" in html
    assert 'Information about ""' not in html
    assert "Description of the app" not in html
    assert "no store description" in html
