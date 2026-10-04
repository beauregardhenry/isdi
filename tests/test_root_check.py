"""Root / jailbreak verdicts. A wrong "Not Detected" misleads the person
being scanned, so each indicator's pass/fail rule is pinned down here."""

import shlex

import pytest

from isdi.scanner import root_check

CLEAN = {
    "getprop ro.build.tags": "release-keys",
    "getenforce": "Enforcing",
    "getprop ro.debuggable": "0",
    "getprop ro.secure": "1",
    "getprop ro.boot.flash.locked": "1",
    "getprop ro.boot.verifiedbootstate": "green",
    "getprop ro.boot.warranty_bit": "0",
}


class _Proc:
    def __init__(self, returncode):
        self.returncode = returncode


@pytest.fixture
def device(monkeypatch):
    """Fake adb: maps each check's device command to (output, returncode).
    Existence checks (su, packages, frida) print nothing on a clean phone."""
    outputs = {cmd: (out, 0) for cmd, out in CLEAN.items()}

    def fake_run_command(cmd, **kw):
        # cmd_str arrives shell-quoted for the host shell; undo that.
        (device_cmd,) = shlex.split(kw["cmd_str"])
        out, rc = outputs.get(device_cmd, ("", 0))
        p = _Proc(rc)
        p.output = out
        return p

    monkeypatch.setattr(root_check, "run_command", fake_run_command)
    monkeypatch.setattr(root_check, "catch_err", lambda p, cmd="": p.output)
    return outputs


def _cmd(name):
    return next(
        c["cmd_str"] for c in root_check.ANDROID_ROOT_INDICATORS if c["name"] == name
    )


def test_clean_device_is_not_rooted(device):
    assert root_check.check_android_root("SER1", "adb") == (False, [])


@pytest.mark.parametrize(
    "name, output",
    [
        ("selinux_permissive", "Permissive"),
        ("ro_debuggable", "1"),
        ("bootloader_unlocked", "0"),
        ("verified_boot_state", "orange"),
        ("build_tags", "test-keys"),
    ],
)
def test_unexpected_value_is_reported(device, name, output):
    device[_cmd(name)] = (output, 0)
    rooted, reasons = root_check.check_android_root("SER1", "adb")
    assert rooted is True
    assert len(reasons) == 1 and f"'{name}'" in reasons[0] and output in reasons[0]


def test_value_comparison_ignores_case(device):
    device[_cmd("verified_boot_state")] = ("GREEN", 0)
    assert root_check.check_android_root("SER1", "adb") == (False, [])


@pytest.mark.parametrize(
    "name, output",
    [
        ("su_binary", "/system/xbin/su"),
        ("root_package", "package:com.topjohnwu.magisk"),
        ("frida_server", "shell  1234  frida-server"),
    ],
)
def test_existence_check_reports_anything_found(device, name, output):
    device[_cmd(name)] = (output, 0)
    rooted, reasons = root_check.check_android_root("SER1", "adb")
    assert rooted is True and f"'{name}'" in reasons[0]


def test_package_prefix_is_stripped_from_reason(device):
    device[_cmd("root_package")] = ("package:com.topjohnwu.magisk", 0)
    _, reasons = root_check.check_android_root("SER1", "adb")
    assert "'com.topjohnwu.magisk'" in reasons[0]


def test_failed_command_is_not_counted_as_rooted(device):
    """A command that errors (locked screen, adb auth) is inconclusive,
    not evidence of root."""
    device[_cmd("selinux_permissive")] = ("", 1)
    assert root_check.check_android_root("SER1", "adb") == (False, [])


def test_missing_samsung_prop_is_skipped(device):
    device[_cmd("samsung_knox_warranty_bit")] = ("", 0)
    assert root_check.check_android_root("SER1", "adb") == (False, [])


def test_samsung_warranty_bit_tripped(device):
    device[_cmd("samsung_knox_warranty_bit")] = ("1", 0)
    rooted, reasons = root_check.check_android_root("SER1", "adb")
    assert rooted and "samsung_knox_warranty_bit" in reasons[0]


def test_reasons_accumulate(device):
    device[_cmd("selinux_permissive")] = ("Permissive", 0)
    device[_cmd("su_binary")] = ("/sbin/su", 0)
    rooted, reasons = root_check.check_android_root("SER1", "adb")
    assert rooted and len(reasons) == 2


# ---------------------------------------------------------------- iOS


@pytest.fixture(params=["async", "sync"])
def lockdown(monkeypatch, request):
    """Fake pymobiledevice3 lockdown client, async (current pymobiledevice3)
    or blocking (older); set .afc2 to the outcome."""
    import asyncio

    asynchronous = request.param == "async"

    def call(result):
        if not asynchronous:
            return result()

        async def run():
            return result()

        return run()

    class Service:
        closed = False

        def close(self):
            return call(lambda: setattr(Service, "closed", True))

    class Client:
        afc2 = "refused"
        closed = False

        def start_lockdown_service(self, name):
            assert name == "com.apple.afc2"

            def outcome():
                if Client.afc2 == "refused":
                    raise RuntimeError("InvalidService")
                return Service()

            if Client.afc2 == "timeout":

                async def hang():
                    await asyncio.sleep(10)

                return hang()
            return call(outcome)

        def close(self):
            return call(lambda: setattr(Client, "closed", True))

    def create_using_usbmux(serial):
        assert serial == "UDID"
        return call(Client)

    monkeypatch.setattr(root_check, "create_using_usbmux", create_using_usbmux)
    monkeypatch.setattr(root_check, "AFC2_TIMEOUT", 0.05)
    Client.service = Service
    return Client


def test_the_installed_pymobiledevice3_matches_how_it_is_called():
    """The afc2 check was silently dead: it passed udid= and called
    start_service, neither of which pymobiledevice3 has."""
    import inspect

    from pymobiledevice3.lockdown import LockdownClient, create_using_usbmux

    assert "serial" in inspect.signature(create_using_usbmux).parameters
    assert hasattr(LockdownClient, "start_lockdown_service")


def test_ios_afc2_client_is_closed(lockdown):
    lockdown.afc2 = "open"
    root_check.check_ios_jailbreak("UDID", "pmd3", [])
    assert lockdown.closed and lockdown.service.closed


def test_ios_clean_device(lockdown):
    rooted, reasons = root_check.check_ios_jailbreak("UDID", "pmd3", [])
    assert rooted is False and "cannot be ruled out" in reasons[0]


def test_ios_afc2_service_means_jailbroken(lockdown):
    lockdown.afc2 = "open"
    rooted, reasons = root_check.check_ios_jailbreak("UDID", "pmd3", [])
    assert rooted is True and "afc2" in reasons[0]


@pytest.mark.parametrize("appid", sorted(root_check.IOS_JAILBREAK_PACKAGES))
def test_ios_jailbreak_app_detected(lockdown, appid):
    rooted, reasons = root_check.check_ios_jailbreak(
        "UDID",
        "pmd3",
        [{"Identifier": "com.apple.mobilesafari"}, {"Identifier": appid}],
    )
    assert rooted is True and appid in reasons[0]


def test_ios_timeout_is_inconclusive(lockdown):
    lockdown.afc2 = "timeout"
    rooted, reasons = root_check.check_ios_jailbreak("UDID", "pmd3", [])
    assert rooted is None and any("timed out" in r for r in reasons)
