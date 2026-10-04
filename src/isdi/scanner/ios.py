"""Scanning iPhones, through pymobiledevice3."""

import json
import logging
import os
import shlex
import time
from typing import Dict, List, Optional, Tuple

from isdi.config import get_config

from .runcmd import catch_err, run_command

cfg = get_config()
from .base import AppScanner


class IosScanner(AppScanner):
    """Scanner for iOS devices using pymobiledevice3."""

    # A live scan reads the phone in device_info() and again in get_apps();
    # reuse the first read for the rest of that scan only.
    DUMP_REUSE_SECONDS = 120

    def __init__(self):
        super().__init__("ios", cfg.LIBIMOBILEDEVICE_PATH)
        self._last_dump: Optional[Tuple[str, float]] = None

    def _dump_for_scan(self, serial: str, fresh: bool) -> bool:
        """Dump the phone unless this scan already did (fresh=False only)."""
        now = time.monotonic()
        if (
            not fresh
            and self._last_dump is not None
            and self._last_dump[0] == serial
            and now - self._last_dump[1] < self.DUMP_REUSE_SECONDS
            and os.path.exists(self.dump_path(serial))
        ):
            return True
        self._last_dump = None
        if not self._dump_phone(serial):
            return False
        self._last_dump = (serial, now)
        return True

    def devices(self) -> List[str]:
        """Get list of connected iOS devices."""
        cmd = "{cli} usbmux list"
        p = run_command(cmd, cli=self.cli)
        output = catch_err(p, cmd=cmd).strip()

        try:
            if not output:
                return []
            # Strip any non-JSON preamble (e.g. download warnings from pymobiledevice3)
            json_start = output.find("[")
            if json_start == -1:
                return []
            data = json.loads(output[json_start:])
            return [d.get("Identifier", "") for d in data if "Identifier" in d]
        except json.JSONDecodeError as e:
            logging.error("Failed to parse the iOS device list: %s", e)
            return []

    def get_apps(self, serialno: str) -> List[str]:
        """Get installed apps from dump."""
        if not self._dump_for_scan(serialno, fresh=False):
            logging.error("Failed to dump iOS device")
            return []

        result = self._load_dump(serialno)
        if not result or not self.ddump:
            logging.error("Failed to load iOS dump")
            return []

        return self.ddump.installed_apps()

    def get_app_titles(self, serialno: str) -> Dict[str, str]:
        """Get iOS app titles as dict: {appId: title}."""
        return self.ddump.installed_apps_titles() if self.ddump else {}

    def device_info(self, serial: str) -> Tuple[str, Dict]:
        """Get iOS device info. Starts a scan, so always reads the phone."""
        if not self._dump_for_scan(serial, fresh=True):
            return "Unknown iOS Device", {}

        self._load_dump(serial)
        if self.ddump:
            return self.ddump.device_info()
        return "Unknown iOS Device", {}

    def isrooted(self, serial: str) -> Tuple[Optional[bool], List[str]]:
        """Check if iOS device is jailbroken."""
        from isdi.scanner.root_check import check_ios_jailbreak

        apps = self.ddump.appinfo if self.ddump else []
        return check_ios_jailbreak(serial, self.cli, apps)

    def uninstall(self, serial: str, appid: str) -> bool:
        """Uninstall an app."""
        cmd = "{cli} apps uninstall --udid {serial} {appid}"
        p = run_command(
            cmd, cli=self.cli, serial=shlex.quote(serial), appid=shlex.quote(appid)
        )
        output = catch_err(p, cmd=cmd)
        return "Success" in output or "uninstalled" in output.lower()
