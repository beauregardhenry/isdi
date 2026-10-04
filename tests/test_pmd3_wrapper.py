"""The Termux wrapper around pymobiledevice3: it must point usbmux at
Termux's socket, and pass through to pymobiledevice3's own command line."""

import importlib
import sys

import pymobiledevice3.osu.os_utils as os_utils
import pymobiledevice3.usbmux as usbmux
import pytest


@pytest.fixture
def wrapper(monkeypatch):
    """Import the wrapper, undoing its patches afterwards (they are global
    to pymobiledevice3)."""
    monkeypatch.setattr(os_utils, "is_wsl", os_utils.is_wsl)
    monkeypatch.setattr(
        usbmux.MuxConnection, "USBMUXD_PIPE", usbmux.MuxConnection.USBMUXD_PIPE
    )
    sys.modules.pop("isdi.scanner.pmd3_wrapper", None)
    return importlib.import_module("isdi.scanner.pmd3_wrapper")


def test_patches_usbmux_for_termux(wrapper):
    assert usbmux.MuxConnection.USBMUXD_PIPE == (
        "/data/data/com.termux/files/usr/var/run/usbmuxd"
    )
    assert os_utils.is_wsl() is False


def test_runs_pymobiledevice3(wrapper, monkeypatch):
    import pymobiledevice3.__main__ as pmd3_main

    monkeypatch.setattr(pmd3_main, "main", lambda: 7)
    assert wrapper.main() == 7


def test_the_patches_are_undone_for_other_tests():
    assert usbmux.MuxConnection.USBMUXD_PIPE != (
        "/data/data/com.termux/files/usr/var/run/usbmuxd"
    )
