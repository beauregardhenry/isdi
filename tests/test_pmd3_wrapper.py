"""ISDi on Termux: pymobiledevice3 must look for usbmuxd's socket under
Termux's prefix, both through the wrapper command and in ISDi's own
process (the afc2 and supervision checks)."""

import asyncio

import pymobiledevice3.osu.os_utils as os_utils
import pymobiledevice3.usbmux as usbmux
import pytest

from isdi.scanner import pmd3_wrapper

TERMUX_PREFIX = "/data/data/com.termux/files/usr"


@pytest.fixture(autouse=True)
def undo_patches(monkeypatch):
    """The patches are global to pymobiledevice3: undo them after each test."""
    monkeypatch.setattr(os_utils, "is_wsl", os_utils.is_wsl)
    monkeypatch.setattr(
        usbmux.MuxConnection, "USBMUXD_PIPE", usbmux.MuxConnection.USBMUXD_PIPE
    )


def _socket_path():
    """Where pymobiledevice3 would connect to usbmuxd now."""
    address, _family = usbmux.MuxConnection._resolve_usbmux_address()
    return address


def test_importing_the_module_patches_nothing():
    import importlib

    importlib.reload(pmd3_wrapper)
    assert _socket_path() == "/var/run/usbmuxd"


def test_the_patches_move_usbmux_to_termuxs_socket(monkeypatch):
    monkeypatch.delenv("USBMUXD_SOCKET_ADDRESS", raising=False)
    pmd3_wrapper.apply_patches()
    assert _socket_path() == pmd3_wrapper.TERMUX_USBMUXD
    assert os_utils.is_wsl() is False


@pytest.mark.parametrize(
    "prefix, patched",
    [(TERMUX_PREFIX, True), (None, False), ("/usr/local", False)],
)
def test_in_process_patch_only_on_termux(monkeypatch, prefix, patched):
    monkeypatch.delenv("USBMUXD_SOCKET_ADDRESS", raising=False)
    if prefix is None:
        monkeypatch.delenv("PREFIX", raising=False)
    else:
        monkeypatch.setenv("PREFIX", prefix)
    pmd3_wrapper.patch_if_termux()
    assert (_socket_path() == pmd3_wrapper.TERMUX_USBMUXD) is patched


def test_the_command_runs_pymobiledevice3_patched(monkeypatch):
    import pymobiledevice3.__main__ as pmd3_main

    seen = []
    monkeypatch.setattr(pmd3_main, "main", lambda: seen.append(_socket_path()) or 7)
    assert pmd3_wrapper.main() == 7
    assert seen == [pmd3_wrapper.TERMUX_USBMUXD]


@pytest.mark.parametrize("check", ["afc2", "supervision"])
def test_the_in_process_checks_use_termuxs_socket(monkeypatch, check):
    """Before 1.9.1 they connected to /var/run/usbmuxd on Termux too, so
    both always reported "could not check" there."""
    import pymobiledevice3.lockdown as lockdown

    from isdi.scanner import ios_management, root_check

    monkeypatch.setenv("PREFIX", TERMUX_PREFIX)
    monkeypatch.delenv("USBMUXD_SOCKET_ADDRESS", raising=False)
    seen = []

    def connect(serial):
        seen.append(_socket_path())
        raise ConnectionError("no phone in the test")

    monkeypatch.setattr(root_check, "create_using_usbmux", connect)
    monkeypatch.setattr(lockdown, "create_using_usbmux", connect)
    with pytest.raises(ConnectionError):
        if check == "afc2":
            asyncio.run(root_check._afc2_query("UDID"))
        else:
            asyncio.run(ios_management._read("UDID"))
    assert seen == [pmd3_wrapper.TERMUX_USBMUXD]
