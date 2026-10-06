"""Scanning Android phones, through adb."""

import contextlib
import logging
import os
import re
import shlex
import subprocess
from datetime import datetime
from typing import Dict, List, Tuple

from isdi.config import get_config

from . import parse_dump
from .runcmd import catch_err, run_command

cfg = get_config()
from .base import AppScanner, _pseudonym, raw_path


class AndroidScanner(AppScanner):
    """Scanner for Android devices using adb."""

    def __init__(self):
        super().__init__("android", cfg.ADB_PATH)

    def _dump_phone(self, serial: str) -> bool:
        """Dump Android device info by running adb commands directly.

        Runs adb via self.cli (cfg.ADB_PATH) so the same binary Python uses
        is used here, avoiding bash-environment adb detection issues on WSL.
        """
        dumpf = self.dump_path(serial)
        os.makedirs(os.path.dirname(dumpf), exist_ok=True)

        json_cache = dumpf.rsplit(".", 1)[0] + ".json"
        if os.path.exists(json_cache):
            os.unlink(json_cache)
        self.ddump = None
        # Only for an unredacted evidence copy: the adb output as received.
        keep_raw = serial in self.unredacted_serials

        logging.info("Dumping android device %s...", _pseudonym(serial))

        services = [
            "package",
            "location",
            "media.camera",
            "netpolicy",
            "mount",
            "cpuinfo",
            "dbinfo",
            "meminfo",
            "procstats",
            "batterystats",
            "netstats detail",
            "usagestats",
            "activity",
            "appops",
            "device_policy",
        ]

        def _run(*args, timeout=120) -> str:
            try:
                r = subprocess.run(
                    [self.cli, "-s", serial, *args],
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    errors="replace",
                )
                return r.stdout
            except subprocess.TimeoutExpired:
                logging.warning("adb timeout: %s", args[:2])
                return ""

        try:
            raw = (
                open(raw_path(dumpf), "w", encoding="utf-8", errors="replace")
                if keep_raw
                else contextlib.nullcontext()
            )
            with open(dumpf, "w", encoding="utf-8", errors="replace") as f, raw as r:

                def write(header, out, processed):
                    # Email addresses are redacted from every section.
                    f.write(header + parse_dump.redact_emails(processed))
                    if r:
                        r.write(header + out)

                for svc in services:
                    out = _run("shell", "dumpsys", *svc.split())
                    write(
                        f"\nDUMP OF SERVICE {svc}\n",
                        out,
                        parse_dump.normalize_dumpsys(out),
                    )

                out = _run("shell", "cat", "/proc/net/xt_qtaguid/stats", timeout=30)
                write("\nDUMP OF SERVICE net_stats\n", out, out.replace(" ", ","))

                for ns in ("secure", "system", "global"):
                    out = _run("shell", "settings", "list", ns, timeout=30)
                    write(
                        f"\nDUMP OF SETTINGS {ns}\n",
                        out,
                        parse_dump.normalize_dumpsys(out),
                    )

            size = os.path.getsize(dumpf)
            if size < 5000:
                logging.error(
                    f"Android dump too small ({size} bytes) — "
                    f"{self.cli} may not be reaching device {_pseudonym(serial)}"
                )
                return False
            logging.info(f"Dump completed: {dumpf} ({size} bytes)")
            return True
        except Exception as e:
            logging.error(f"Android dump failed: {e}")
            return False

    def get_device_owner_apps(self, serialno: str) -> set:
        """Return package names that hold device owner privilege on the device."""
        cmd = "{cli} -s {serial} shell dpm list-owners"
        s = catch_err(
            run_command(cmd, cli=self.cli, serial=shlex.quote(serialno)), cmd=cmd
        )
        device_owner_apps: set = set()
        if not s:
            return device_owner_apps
        for line in s.splitlines():
            if "DeviceOwner" in line and "admin=" in line:
                m = re.search(r"admin=([a-zA-Z0-9_.]+)/", line)
                if m:
                    device_owner_apps.add(m.group(1))
        return device_owner_apps

    def devices(self) -> List[str]:
        """Get list of connected Android devices."""
        cmd = "{cli} devices | tail -n +2"
        p = run_command(cmd, cli=self.cli)
        output = catch_err(p, cmd=cmd).strip()

        devices = []
        for line in output.split("\n"):
            parts = line.split()
            if len(parts) == 2 and parts[1] == "device":
                devices.append(parts[0])
        return devices

    def get_apps(self, serialno: str) -> List[str]:
        """Get installed apps from dump."""
        # Always start with a fresh dump — delete old txt so _load_dump re-runs _dump_phone.
        # This also ensures the stale JSON cache (cleaned up inside _dump_phone) is never reused.
        dumpf = self.dump_path(serialno)
        if os.path.exists(dumpf):
            os.unlink(dumpf)
        self.ddump = None

        result = self._load_dump(serialno)
        if not result or not self.ddump:
            logging.error("Cannot load dump for %s", _pseudonym(serialno))
            return []
        return self.ddump.all_apps()

    def device_info(self, serial: str) -> Tuple[str, Dict]:
        """Get Android device info."""
        m: Dict[str, str] = {}
        try:
            props = {
                "brand": "ro.product.brand",
                "model": "ro.product.model",
                "version": "ro.build.version.release",
            }

            for key, prop in props.items():
                cmd = "{cli} -s {serial} shell getprop {prop}"
                p = run_command(
                    cmd, cli=self.cli, serial=shlex.quote(serial), prop=prop
                )
                output = catch_err(p, cmd=cmd).strip()
                m[key] = output or "Unknown"

            m["last_full_charge"] = datetime.now().isoformat()

            info_str = f"{m['brand']} {m['model']} (Android {m['version']})"
            return info_str, m
        except Exception as e:
            logging.error(f"Error getting device info: {e}")
            return "Unknown Device", {}

    def isrooted(self, serial: str) -> Tuple[bool, List[str]]:
        """Check if Android device is rooted."""
        from isdi.scanner.root_check import check_android_root

        return check_android_root(serial, self.cli)

    def uninstall(self, serial: str, appid: str) -> bool:
        """Uninstall an app."""
        cmd = "{cli} -s {serial} uninstall {appid}"
        p = run_command(
            cmd, cli=self.cli, serial=shlex.quote(serial), appid=shlex.quote(appid)
        )
        output = catch_err(p, cmd=cmd)
        return "Success" in output
