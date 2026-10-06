"""An iPhone scan from start to finish, through the web scan: the real
ios_scan.sh runs a fake `pymobiledevice3`, and the dump goes through the
parser, the blocklist, the supervision/profiles check, the database, the
results page and the client summary. Each piece has its own tests; this
one catches a broken link between them, which would show as a clean phone."""

import json
import os
import stat
import sys
import uuid
from pathlib import Path

import pytest

from isdi.scanner import blocklist, db, ios_management

UDID = "00008110-000A1B2C3D4E5F"
STALKER = "com.example.ios.stalker"
LOCATOR = "com.example.ios.locator"

APPS = {
    "com.apple.mobilesafari": {
        "CFBundleIdentifier": "com.apple.mobilesafari",
        "CFBundleExecutable": "MobileSafari",
        "CFBundleDisplayName": "Safari",
        "ApplicationType": "System",
    },
    STALKER: {
        "CFBundleIdentifier": STALKER,
        "CFBundleExecutable": "Helper",
        "CFBundleDisplayName": "System Helper",
        "ApplicationType": "User",
        "NSLocationAlwaysUsageDescription": "Needed.",
    },
    LOCATOR: {
        "CFBundleIdentifier": LOCATOR,
        "CFBundleExecutable": "Locator",
        "CFBundleDisplayName": "Family Locator",
        "ApplicationType": "User",
    },
}
DEVINFO = {
    "DeviceClass": "iPhone",
    "ProductType": "iPhone14,5",
    "ProductVersion": "18.0",
    "SerialNumber": "not-copied-into-results",
}

FAKE_PMD3 = f"""#!{sys.executable}
import sys
args = sys.argv[1:]
if args[:2] == ["apps", "list"]:
    print({json.dumps(json.dumps(APPS))})
elif args[:2] == ["lockdown", "info"]:
    print({json.dumps(json.dumps(DEVINFO))})
else:
    sys.exit(2)
"""


@pytest.fixture
def iphone(tmp_path, monkeypatch):
    """A fake pymobiledevice3 on PATH (what ios_scan.sh runs), a managed
    phone for the supervision check, and two listed apps."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    tool = bin_dir / "pymobiledevice3"
    tool.write_text(FAKE_PMD3)
    tool.chmod(tool.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.delenv("PREFIX", raising=False)

    async def managed(serial):
        assert serial == UDID
        profiles = {
            "ProfileMetadata": {
                "com.example.mdm": {
                    "PayloadDisplayName": "Remote Management",
                    "PayloadOrganization": "Example Org",
                }
            }
        }
        return profiles, {"IsSupervised": True, "OrganizationName": "Example Org"}

    monkeypatch.setattr(ios_management, "_read", managed)
    monkeypatch.setitem(
        blocklist._FLAGS_BY_APPID,
        STALKER,
        {"appId": STALKER, "flag": "stalkerware", "title": "Stalker"},
    )
    monkeypatch.setitem(
        blocklist._FLAGS_BY_APPID,
        LOCATOR,
        {"appId": LOCATOR, "flag": "dual-use", "title": ""},
    )


def test_an_iphone_scan_end_to_end(app, client, iphone):
    from isdi.web.view import scan as scan_view

    clientid = "20260101_001"  # the test client's session
    owner = f"Owner-{uuid.uuid4().hex[:6]}"
    with app.test_request_context():
        result, status = scan_view._run_live_scan(clientid, "ios", owner, UDID)
    assert status == 200, result.get("error")

    # Classified, worst first, under the name the home screen shows.
    apps = result["apps"]
    assert list(apps) == [STALKER, LOCATOR, "com.apple.mobilesafari"]
    assert apps[STALKER]["flags"] == ["stalkerware"]
    assert apps[STALKER]["title"] == "System Helper"
    assert apps[LOCATOR]["flags"] == ["dual-use"]
    assert apps["com.apple.mobilesafari"]["flags"] == ["system-app"]
    assert result["device_name"] == "iPhone 13 (running iOS 18.0)"
    assert "Supervised</span> by Example Org" in result["management"]
    assert "Remote Management (Example Org)" in result["management"]

    # Saved: the management result with the scan, encrypted; no raw dump kept.
    scanid = result["scanid"]
    with app.app_context():
        saved = db.get_scan_res_from_db(scanid)
        assert saved["device_manufacturer"] == "Apple"
        management = json.loads(saved["device_management"])
        assert management["checked"] and management["supervised"]
        assert [p["name"] for p in management["profiles"]] == ["Remote Management"]
    stored = Path(db.DATABASE).read_bytes()
    for secret in (b"Example Org", b"Remote Management", STALKER.encode()):
        assert secret not in stored, f"{secret!r} stored in the clear"
    from isdi.config import get_config

    prefix = get_config().hmac_serial(UDID)
    assert not [f for f in os.listdir(get_config().DUMP_DIR) if f.startswith(prefix)]

    # The saved results page and the client summary read it back.
    page = client.get(f"/scan/saved/{scanid}").get_data(as_text=True)
    assert "Supervised</span> by Example Org" in page and STALKER in page
    summary = client.get(f"/scan/{scanid}/client-summary").get_data(as_text=True)
    assert "Apps known to be used for monitoring" in summary
    assert STALKER in summary
    assert "The phone is supervised by Example Org." in summary
    assert "Apps that can share location or activity" in summary and LOCATOR in summary


def test_an_iphone_that_cannot_be_read_is_not_reported_clean(app, iphone, monkeypatch):
    """If the phone does not answer (locked, not trusted), the scan fails
    with an error: it must not save an empty, "nothing found" result."""
    from isdi.web.view import scan as scan_view

    tool = [p for p in os.environ["PATH"].split(os.pathsep) if p.endswith("bin")][0]
    with open(os.path.join(tool, "pymobiledevice3"), "w") as f:
        f.write(f"#!{sys.executable}\nimport sys\nsys.exit(1)\n")
    with app.app_context():
        before = db.get_db().execute("SELECT COUNT(*) AS n FROM scan_res").fetchone()
    with app.test_request_context():
        result, status = scan_view._run_live_scan("20260101_001", "ios", "x", UDID)
    assert status != 200 and result.get("error")
    assert "scanid" not in result
    with app.app_context():
        after = db.get_db().execute("SELECT COUNT(*) AS n FROM scan_res").fetchone()
    assert dict(after) == dict(before)
