"""`isdi field-test` against the suite's fake Android phone and fake iPhone:
the report says what each part of ISDi recognised, and never holds an app
id, a name or the serial."""

import json

import pytest
from click.testing import CliRunner

import isdi.scanner as scanner
from isdi import fieldtest
from tests.test_ios_end_to_end import APPS as IOS_APPS
from tests.test_ios_end_to_end import UDID, iphone  # noqa: F401
from tests.test_scanner_pipeline import FAKE_ADB, SERIAL, STALKER, _fake_tool


@pytest.fixture
def android_phone(tmp_path, monkeypatch):
    """fieldtest.run makes its own scanner: give it the fake adb."""
    real = scanner.AndroidScanner
    adb = _fake_tool(tmp_path, "adb", FAKE_ADB)

    def make():
        sc = real()
        sc.cli = adb
        return sc

    monkeypatch.setattr(scanner, "AndroidScanner", make)
    monkeypatch.setattr(scanner.AppScanner, "app_info_conn", None)
    return adb


def _no_phone_data(report, *secrets):
    text = json.dumps(report)
    for secret in secrets:
        assert secret not in text, secret


def test_android_report(android_phone):
    report = fieldtest.run("android")
    assert report["result"] == "done" and report["connected_devices"] == 1
    assert report["device"] == {
        "manufacturer": "google",
        "model": "Pixel 8",
        "android_version": "14",
    }
    assert {"package", "secure", "device_policy"} <= set(report["dump"]["sections"])
    access = report["special_access"]
    assert access["secure_settings"]["enabled_accessibility_services"] == {
        "present": True,
        "entries": 1,
    }
    assert access["enabled_device_admins_heading"] is True
    assert access["apps_per_power"] == {
        "accessibility": 1,
        "device-admin": 1,
        "notification-access": 1,
    }
    assert report["apps"] == {
        "installed": 2,
        "system": 0,
        "off_store": 1,
        "device_owner": 1,
    }
    assert "su_binary" in report["root_check"]["checks_fired"]
    _no_phone_data(report, SERIAL, STALKER, "com.whatsapp", "Watcher", "Listener")


def test_the_dump_is_deleted_afterwards(android_phone):
    import os

    from isdi.config import get_config

    fieldtest.run("android")
    prefix = get_config().hmac_serial(SERIAL)
    assert not [f for f in os.listdir(get_config().DUMP_DIR) if f.startswith(prefix)]


def test_ios_report(iphone, monkeypatch):  # noqa: F811
    # The fixture fakes the dump script; the device list too.
    monkeypatch.setattr(scanner.IosScanner, "devices", lambda self: [UDID])
    report = fieldtest.run("ios")
    assert report["result"] == "done"
    assert report["device"]["model"] == "iPhone 13" and report["device"]["model_known"]
    apps = report["apps"]
    assert apps["installed"] == 3 and apps["system"] == 1
    assert apps["name_taken_from"] == {"CFBundleDisplayName": 3}
    assert "CFBundleDisplayName" in apps["app_fields_seen"]
    management = report["management"]
    assert management["read"] and management["profiles"] == 1
    assert management["profile_metadata_keys"] == [
        "PayloadDisplayName",
        "PayloadOrganization",
    ]
    assert management["cloud_configuration_keys"] == [
        "IsSupervised",
        "OrganizationName",
    ]
    assert management["parsed"] == {"supervised": True}
    # No usbmuxd in the test: the afc2 check reports why it could not run.
    assert report["afc2"]["opened"] is False and report["afc2"]["error"]
    _no_phone_data(
        report,
        UDID,
        *IOS_APPS,
        "System Helper",
        "Family Locator",
        "Remote Management",
        "Example Org",
        "com.example.mdm",
    )


def test_no_phone_connected(monkeypatch):
    class NoPhones:
        def devices(self):
            return []

    monkeypatch.setattr(scanner, "IosScanner", NoPhones)
    report = fieldtest.run("ios")
    assert report["result"] == "no phone found" and report["connected_devices"] == 0
    assert fieldtest.run.__defaults__ == (None,)


def test_a_phone_that_is_not_connected(android_phone):
    assert fieldtest.run("android", "OTHER123")["result"] == (
        "that phone is not connected"
    )


def test_a_report_holding_an_identifier_is_refused():
    with pytest.raises(fieldtest.NotPrivate):
        fieldtest.assert_private({"apps": ["com.secret.app"]}, ["com.secret.app"])
    assert fieldtest.assert_private({"n": 1}, ["com.secret.app"]) == {"n": 1}


def _cli(*args, input=None):
    from isdi import cli

    return CliRunner().invoke(cli.cli, ["field-test", *args], input=input)


def test_the_command_asks_for_a_test_phone(android_phone, tmp_path):
    out = tmp_path / "report.txt"
    refused = _cli("android", "-o", str(out), input="n\n")
    assert refused.exit_code == 1 and not out.exists()
    done = _cli("android", "-o", str(out), input="y\n")
    assert done.exit_code == 0, done.output
    text = out.read_text()
    assert text.startswith("ISDi field test.") and '"result": "done"' in text
    assert STALKER not in text and SERIAL not in text


def test_the_command_writes_nothing_if_the_report_is_not_private(
    android_phone, tmp_path, monkeypatch
):
    def leaky(device, serial=None):
        raise fieldtest.NotPrivate("the report would contain 1 identifier(s)")

    monkeypatch.setattr(fieldtest, "run", leaky)
    out = tmp_path / "report.txt"
    res = _cli("android", "--yes", "-o", str(out))
    assert res.exit_code == 1 and "No report was written" in res.output
    assert not out.exists()
