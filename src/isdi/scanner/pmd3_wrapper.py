"""pymobiledevice3 for Termux (ISDi running on an Android phone).

Termux keeps usbmuxd's socket under its own prefix, not at
/var/run/usbmuxd, and pymobiledevice3's WSL detection misfires there.
apply_patches() fixes both; pymobiledevice3's Linux code reads
MuxConnection.USBMUXD_PIPE each time it connects.

- As a command, `python3 -m isdi.scanner.pmd3_wrapper <args>` runs
  pymobiledevice3's own command line with the patches applied (ISDi's
  subprocess calls and ios_scan.sh use it on Termux).
- In ISDi's own process, the jailbreak (afc2) and supervision checks call
  the library directly: they call patch_if_termux() first. Importing this
  module patches nothing by itself.
"""

import os
import sys

import pymobiledevice3.osu.os_utils as os_utils_module
import pymobiledevice3.usbmux as usbmux_module

TERMUX_USBMUXD = "/data/data/com.termux/files/usr/var/run/usbmuxd"


def _fake_is_wsl():
    """Prevent pymobiledevice3 from detecting WSL incorrectly."""
    return False


def is_termux() -> bool:
    return "com.termux" in os.environ.get("PREFIX", "")


def apply_patches() -> None:
    os_utils_module.is_wsl = _fake_is_wsl
    usbmux_module.MuxConnection.USBMUXD_PIPE = TERMUX_USBMUXD


def patch_if_termux() -> None:
    """For in-process use: patch only when running under Termux."""
    if is_termux():
        apply_patches()


def main():
    """Entry point: call pymobiledevice3 with patches applied."""
    apply_patches()
    from pymobiledevice3.__main__ import main as pmd3_main

    return pmd3_main()


if __name__ == "__main__":
    sys.exit(main())
