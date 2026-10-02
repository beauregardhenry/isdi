"""Parsing of adb / pymobiledevice3 output and how a scan's results are
assembled. A misparse here silently drops a phone or an app from the scan."""

import shlex

import pytest

import isdi.scanner as scanner
from isdi.scanner import AndroidScanner, AppScanner, IosScanner


@pytest.fixture
def tool_output(monkeypatch):
    """Fake run_command/catch_err: record the shell command, return canned
    output. Set tool_output.text before calling the scanner."""

    class Out:
        text = ""
        commands = []

    def fake_run_command(cmd, **kw):
        Out.commands.append(cmd.format(**kw))
        return object()

    monkeypatch.setattr(scanner, "run_command", fake_run_command)
    monkeypatch.setattr(scanner, "catch_err", lambda p, cmd="": Out.text)
    Out.commands = []
    return Out


def test_android_devices_only_lists_authorized_devices(tool_output):
    tool_output.text = (
        "R58M12ABCDE\tdevice\n"
        "emulator-5554\tdevice\n"
        "ZY224F8TKG\tunauthorized\n"
        "192.168.1.5:5555\toffline\n"
        "\n"
    )
    assert AndroidScanner().devices() == ["R58M12ABCDE", "emulator-5554"]


def test_android_devices_none_connected(tool_output):
    tool_output.text = ""
    assert AndroidScanner().devices() == []


def test_ios_devices_skips_warning_preamble(tool_output):
    tool_output.text = (
        "2026-10-02 WARNING developer disk image not mounted\n"
        '[{"Identifier": "00008030-001A2B3C4D5E", "ConnectionType": "USB"},'
        ' {"ConnectionType": "Network"}]'
    )
    assert IosScanner().devices() == ["00008030-001A2B3C4D5E"]


@pytest.mark.parametrize("text", ["", "usbmuxd not running", "[not json"])
def test_ios_devices_bad_output(tool_output, text):
    tool_output.text = text
    assert IosScanner().devices() == []


def test_device_owner_parsing(tool_output):
    """Pins the parser to the `dpm list-owners` line shape; only
    DeviceOwner entries count, not ProfileOwner."""
    tool_output.text = (
        "2 owners:\n"
        "User  0: admin=com.example.mdm/.AdminReceiver,DeviceOwner\n"
        "User 10: admin=com.example.work/.Receiver,ProfileOwner\n"
    )
    assert AndroidScanner().get_device_owner_apps("SER1") == {"com.example.mdm"}


def test_device_owner_none(tool_output):
    tool_output.text = "no owners"
    assert AndroidScanner().get_device_owner_apps("SER1") == set()


@pytest.mark.parametrize(
    "cls, expected_prefix",
    [
        (AndroidScanner, ["-s", "SER 1"]),
        (IosScanner, ["apps", "uninstall", "--udid", "SER 1"]),
    ],
)
def test_uninstall_passes_serial_and_appid_as_single_arguments(
    tool_output, cls, expected_prefix
):
    tool_output.text = "Success"
    sc = cls()
    evil = "com.x; rm -rf ~"
    assert sc.uninstall(serial="SER 1", appid=evil) is True
    argv = shlex.split(tool_output.commands[-1])
    assert argv[-1] == evil
    joined = " ".join(argv)
    assert " ".join(expected_prefix) in joined


def test_uninstall_failure(tool_output):
    tool_output.text = "Failure [DELETE_FAILED_INTERNAL_ERROR]"
    assert AndroidScanner().uninstall(serial="SER1", appid="com.x") is False


# ------------------------------------------------------------ find_spyapps


@pytest.fixture
def android(monkeypatch):
    """AndroidScanner with the phone and app-info db replaced by stubs."""
    sc = AndroidScanner()
    monkeypatch.setattr(AppScanner, "app_info_conn", None)
    sc.installed = []
    sc.offstore = []
    sc.system = []
    sc.owners = set()
    monkeypatch.setattr(sc, "get_apps", lambda s: list(sc.installed))
    monkeypatch.setattr(sc, "get_offstore_apps", lambda s: list(sc.offstore))
    monkeypatch.setattr(sc, "get_system_apps", lambda s: list(sc.system))
    monkeypatch.setattr(sc, "get_device_owner_apps", lambda s: set(sc.owners))
    return sc


def _stalkerware_appid():
    from isdi.scanner import blocklist

    return next(
        r["appId"] for r in blocklist.APP_FLAGS.data if r["flag"] == "stalkerware"
    )


def test_find_spyapps_no_apps(android):
    assert android.find_spyapps("SER1") == {}


def test_find_spyapps_flags_known_stalkerware_and_sorts_it_first(android):
    stalker = _stalkerware_appid()
    android.installed = ["org.example.calculator", stalker]
    res = android.find_spyapps("SER1")
    assert list(res)[0] == stalker
    assert "stalkerware" in res[stalker]["flags"]
    assert res[stalker]["class_"] == "alert-primary"
    assert res["org.example.calculator"]["flags"] == []


def test_find_spyapps_adds_device_owner_flag(android):
    android.installed = ["org.example.a", "com.example.mdm"]
    android.owners = {"com.example.mdm", "not.installed"}
    res = android.find_spyapps("SER1")
    assert res["com.example.mdm"]["flags"] == ["device-owner"]
    assert res["com.example.mdm"]["score"] == 1.0
    assert "not.installed" not in res
    assert list(res)[0] == "com.example.mdm"


def test_find_spyapps_result_fields(android):
    android.installed = ["org.example.a"]
    android.offstore = ["org.example.a"]
    r = android.find_spyapps("SER1")["org.example.a"]
    assert set(r) == {"title", "flags", "score", "class_", "html_flags"}
    assert r["flags"] == ["offstore-app"] and r["class_"] == "alert-warning"


def test_find_spyapps_ties_sorted_by_appid(android):
    android.installed = ["org.c", "org.a", "org.b"]
    assert list(android.find_spyapps("SER1")) == ["org.a", "org.b", "org.c"]
