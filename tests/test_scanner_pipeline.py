"""The scanners end to end against fake `adb` and `pymobiledevice3`
executables: commands really run through the shell, and their output goes
through the same parsing as with a phone."""

import json
import os
import stat
import sys

import pytest

import isdi.scanner as scanner

SERIAL = "R58M12ABCDE"
STALKER = "com.example.stalker"

PACKAGE_DUMPSYS = f"""\
Packages:
  Package [{STALKER}] (5d6e7f8):
    userId=10234
    versionName=2.1
    installerPackageName=null
    User 0: ceDataInode=12345 installed=true hidden=false
      firstInstallTime=2026-09-01 12:00:00
  Package [com.whatsapp] (1a2b3c4):
    userId=10100
    versionName=2.24
    installerPackageName=com.android.vending
    User 0: ceDataInode=222 installed=true hidden=false
      firstInstallTime=2025-01-01 09:00:00
"""

SECURE_SETTINGS = f"""\
accessibility_enabled=1
enabled_accessibility_services={STALKER}/{STALKER}.Watcher
enabled_notification_listeners=com.whatsapp/com.whatsapp.Listener
"""

DEVICE_POLICY = f"""\
Current Device Policy Manager state:
  Enabled Device Admins (User 0, provisioningState: 0):
    {STALKER}/.Admin:
      uid=10234
"""

FAKE_ADB = f"""\
import sys
args = sys.argv[1:]
if args == ["devices"]:
    print("List of devices attached")
    print("{SERIAL}\\tdevice")
    print("emulator-5554\\toffline")
    sys.exit(0)
assert args[0] == "-s", args
serial, rest = args[1], args[2:]
if serial != "{SERIAL}":
    print(f"error: device '{{serial}}' not found", file=sys.stderr)
    sys.exit(1)
props = {{"ro.product.brand": "google", "ro.product.model": "Pixel 8",
         "ro.build.version.release": "14"}}
if rest[:2] == ["shell", "getprop"]:
    print(props.get(rest[2], ""))
elif rest == ["shell", "dpm", "list-owners"]:
    print("Owners:")
    print("  User 0: admin={STALKER}/.Admin,DeviceOwner,Affiliated")
elif rest[:1] == ["uninstall"]:
    print("Success" if rest[1] == "com.whatsapp" else "Failure [DELETE_FAILED]")
elif rest == ["shell", "dumpsys", "package"]:
    sys.stdout.write({PACKAGE_DUMPSYS!r})
elif rest == ["shell", "settings", "list", "secure"]:
    sys.stdout.write({SECURE_SETTINGS!r})
elif rest == ["shell", "dumpsys", "device_policy"]:
    sys.stdout.write({DEVICE_POLICY!r})
else:
    sys.stdout.write("x=1\\n" * 400)
"""


def _fake_tool(tmp_path, name, body):
    path = tmp_path / name
    path.write_text(f"#!{sys.executable}\n" + body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return str(path)


@pytest.fixture
def android(tmp_path, monkeypatch):
    sc = scanner.AndroidScanner()
    monkeypatch.setattr(sc, "cli", _fake_tool(tmp_path, "adb", FAKE_ADB))
    monkeypatch.setattr(scanner.AppScanner, "app_info_conn", None)
    yield sc
    for ext in ("txt", "json"):
        f = sc.dump_path(SERIAL).rsplit(".", 1)[0] + "." + ext
        if os.path.exists(f):
            os.remove(f)


def test_android_lists_only_ready_devices(android):
    assert android.devices() == [SERIAL]


def test_android_device_info(android):
    name, info = android.device_info(SERIAL)
    assert name == "google Pixel 8 (Android 14)"
    assert info["model"] == "Pixel 8" and info["version"] == "14"


def test_android_device_owner_apps(android):
    assert android.get_device_owner_apps(SERIAL) == {STALKER}


def test_android_uninstall_reports_success_and_failure(android):
    assert android.uninstall(SERIAL, "com.whatsapp") is True
    assert android.uninstall(SERIAL, STALKER) is False


def test_android_find_spyapps_end_to_end(android, monkeypatch):
    """Dump the phone, parse it, classify the apps: a sideloaded device-owner
    app comes first, with its flags."""
    from isdi.scanner import blocklist

    monkeypatch.setitem(
        blocklist._FLAGS_BY_APPID,
        STALKER,
        {"appId": STALKER, "flag": "stalkerware", "title": "Stalker"},
    )
    apps = android.find_spyapps(SERIAL)
    assert list(apps) == [STALKER, "com.whatsapp"]
    flags = apps[STALKER]["flags"]
    assert {"stalkerware", "offstore-app", "device-owner"} <= set(flags)
    assert {"accessibility", "device-admin"} <= set(flags)
    assert "notification-access" not in flags
    assert apps["com.whatsapp"]["flags"] == ["notification-access"]
    assert apps["com.whatsapp"]["class_"] == "alert-warning"
    assert android.ddump.info(STALKER)["firstInstallTime"] == "2026-09-01 12:00:00"


def test_android_scan_of_unknown_device_finds_nothing(android):
    assert android.find_spyapps("OTHER123") == {}


FAKE_PMD3 = f"""\
import sys
args = sys.argv[1:]
if args == ["usbmux", "list"]:
    print("Downloading resources...")
    print({json.dumps(json.dumps([{"Identifier": "00008110-000A1B2C3D4E5F", "ConnectionType": "USB"}]))})
elif args[:2] == ["apps", "uninstall"]:
    print("uninstalled" if args[-1] == "com.example.app" else "failed")
else:
    sys.exit(2)
"""


@pytest.fixture
def ios(tmp_path, monkeypatch):
    sc = scanner.IosScanner()
    monkeypatch.setattr(sc, "cli", _fake_tool(tmp_path, "pmd3", FAKE_PMD3))
    return sc


def test_ios_devices_ignore_preamble(ios):
    assert ios.devices() == ["00008110-000A1B2C3D4E5F"]


def test_ios_devices_when_tool_fails(ios, tmp_path, monkeypatch):
    monkeypatch.setattr(
        ios, "cli", _fake_tool(tmp_path, "broken", "import sys; sys.exit(1)")
    )
    assert ios.devices() == []


def test_ios_uninstall(ios):
    assert ios.uninstall("00008110-000A1B2C3D4E5F", "com.example.app") is True
    assert ios.uninstall("00008110-000A1B2C3D4E5F", "com.other") is False


def test_ios_app_titles_from_dump(ios, monkeypatch):
    from isdi.scanner import parse_dump

    fixture = os.path.join(os.path.dirname(__file__), "fixtures", "ios_dump.json")
    ios.ddump = parse_dump.IosDump(fixture)
    titles = ios.get_app_titles("x")
    assert titles["com.example.tracker"]
