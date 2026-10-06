"""The parts of the installed pymobiledevice3 that ISDi relies on, checked
against the real library rather than a fake.

The scanner tests replace pymobiledevice3 with fakes, so they keep passing
when the library changes underneath. That is how the iPhone jailbreak
check (afc2) stayed broken until 1.7.0: the library's API changed, the
fake did not, and the real check failed quietly. CI installs the newest
pymobiledevice3, so a change to anything below fails here instead.
"""

import inspect
import subprocess
import sys

import pytest

lockdown = pytest.importorskip("pymobiledevice3.lockdown")


def _params(func):
    return inspect.signature(func).parameters


def test_connecting_by_serial():
    """root_check._afc2_query and ios_management._read call
    create_using_usbmux(serial=...)."""
    assert "serial" in _params(lockdown.create_using_usbmux)


def test_lockdown_client_starts_services_and_closes():
    """The afc2 check: client.start_lockdown_service(name), then close()."""
    client = lockdown.LockdownClient
    assert "name" in _params(client.start_lockdown_service)
    assert callable(getattr(client, "close", None))
    from pymobiledevice3.service_connection import ServiceConnection

    assert callable(getattr(ServiceConnection, "close", None))


def test_mobile_config_service_reads_profiles_and_supervision():
    """ios_management._read: `async with MobileConfigService(client)`, then
    get_profile_list() and get_cloud_configuration(), with no arguments."""
    from pymobiledevice3.services.mobile_config import MobileConfigService

    assert hasattr(MobileConfigService, "__aenter__")
    assert hasattr(MobileConfigService, "__aexit__")
    assert "lockdown" in _params(MobileConfigService.__init__)
    for name in ("get_profile_list", "get_cloud_configuration"):
        method = getattr(MobileConfigService, name)
        required = [
            p
            for p in list(_params(method).values())[1:]
            if p.default is inspect.Parameter.empty
        ]
        assert required == [], f"{name} now needs {required}"


def test_termux_patches_still_have_something_to_patch():
    """pmd3_wrapper sets these two attributes. Setting an attribute never
    fails, so if the library renamed them the patch would do nothing."""
    import pymobiledevice3.osu.os_utils as os_utils
    import pymobiledevice3.usbmux as usbmux

    assert callable(getattr(os_utils, "is_wsl", None))
    assert hasattr(usbmux.MuxConnection, "USBMUXD_PIPE")


@pytest.mark.parametrize(
    "command",
    [
        ["usbmux", "list"],  # IosScanner.devices
        ["apps", "list"],  # ios_scan.sh
        ["lockdown", "info"],  # ios_scan.sh
        ["apps", "uninstall"],  # IosScanner.uninstall
    ],
)
def test_the_commands_isdi_runs_exist(command):
    """An unknown command exits with 2; these must still be known."""
    r = subprocess.run(
        [sys.executable, "-m", "pymobiledevice3", *command, "--help"],
        capture_output=True,
        timeout=120,
    )
    assert r.returncode == 0, r.stderr.decode(errors="replace")[-500:]


def test_the_lockdown_service_name_isdi_checks_for():
    """ios_management reads the MCInstall service (as Apple Configurator
    does); a rename would make every check "could not check"."""
    from pymobiledevice3.services.mobile_config import MobileConfigService

    assert MobileConfigService.SERVICE_NAME == "com.apple.mobile.MCInstall"
