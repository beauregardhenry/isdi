"""Scanning Android phones, through adb."""

import contextlib
import logging
import os
import re
import subprocess
import tempfile
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

from isdi.config import get_config

from . import apk_signers, parse_dump
from .runcmd import catch_err, is_valid_appid

cfg = get_config()
from .base import APK_COPY_PREFIX, AppScanner, _pseudonym, raw_path

# Where Android keeps installed APKs, as `pm path` prints them. Anything
# else is not used: the path goes back to the phone in `stat` and `pull`.
_APK_PATH_RE = re.compile(
    r"/(data|system|product|vendor|system_ext)/[A-Za-z0-9._~=+@/\-]+\.apk"
)
# Apps larger than this are not copied off the phone: copying takes time
# over USB, and the monitoring apps on the list are a few MB.
MAX_APK_BYTES = 150 * 1024 * 1024


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
                    self.tool("-s", serial, *args),
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
            logging.info("Dump completed for %s (%d bytes)", _pseudonym(serial), size)
            return True
        except Exception as e:
            logging.error("Android dump failed: %s", type(e).__name__)
            return False

    def get_device_owner_apps(self, serialno: str) -> set:
        """Return package names that hold device owner privilege on the device."""
        s = catch_err(
            self.run_tool("-s", serialno, "shell", "dpm", "list-owners"),
            cmd="dpm list-owners",
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

    def _base_apk(self, serial: str, appid: str) -> Optional[str]:
        out = catch_err(
            self.run_tool("-s", serial, "shell", "pm", "path", appid), cmd="pm path"
        )
        paths = [
            line[len("package:") :].strip()
            for line in out.splitlines()
            if line.startswith("package:")
        ]
        # The base APK carries the signature; splits are signed the same.
        paths.sort(key=lambda p: not p.endswith("/base.apk"))
        if not paths or not _APK_PATH_RE.fullmatch(paths[0]) or ".." in paths[0]:
            return None
        return paths[0]

    def signer_certs(
        self, serial: str, appids: List[str]
    ) -> Tuple[Dict[str, Set[str]], Set[str]]:
        """Copy each app's APK off the phone into a private temporary
        folder, read who signed it (apk_signers.py) and delete the copy."""
        found: Dict[str, Set[str]] = {}
        unchecked: Set[str] = set()
        for appid in appids:
            if not is_valid_appid(appid):
                unchecked.add(appid)
                continue
            path = self._base_apk(serial, appid)
            if path is None:
                unchecked.add(appid)
                continue
            size = catch_err(
                self.run_tool("-s", serial, "shell", "stat", "-c", "%s", path),
                cmd="stat",
            ).strip()
            if not size.isdigit() or int(size) > MAX_APK_BYTES:
                unchecked.add(appid)
                continue
            # In the dump folder: owner-only, and emptied at start if a
            # crash leaves a copy behind (base.purge_raw_dumps).
            with tempfile.TemporaryDirectory(
                prefix=APK_COPY_PREFIX, dir=cfg.DUMP_DIR
            ) as tmp:
                dest = os.path.join(tmp, "app.apk")
                catch_err(self.run_tool("-s", serial, "pull", path, dest), cmd="pull")
                try:
                    found[appid] = apk_signers.signer_sha1s(dest)
                except (apk_signers.ApkError, OSError) as e:
                    logging.warning(
                        "Could not read an app's signer: %s", type(e).__name__
                    )
                    unchecked.add(appid)
        logging.info(
            "Signers read for %d of %d sideloaded apps on %s",
            len(found),
            len(appids),
            _pseudonym(serial),
        )
        return found, unchecked

    def devices(self) -> List[str]:
        """Get list of connected Android devices."""
        output = catch_err(self.run_tool("devices"), cmd="adb devices").strip()

        devices = []
        # The first line is the "List of devices attached" header.
        for line in output.split("\n")[1:]:
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
                p = self.run_tool("-s", serial, "shell", "getprop", prop)
                output = catch_err(p, cmd=f"getprop {prop}").strip()
                m[key] = output or "Unknown"

            m["last_full_charge"] = datetime.now().isoformat()

            info_str = f"{m['brand']} {m['model']} (Android {m['version']})"
            return info_str, m
        except Exception as e:
            logging.error("Error getting device info: %s", type(e).__name__)
            return "Unknown Device", {}

    def isrooted(self, serial: str) -> Tuple[bool, List[str]]:
        """Check if Android device is rooted."""
        from isdi.scanner.root_check import check_android_root

        return check_android_root(serial, self.cli)

    def uninstall(self, serial: str, appid: str) -> bool:
        """Uninstall an app."""
        output = catch_err(
            self.run_tool("-s", serial, "uninstall", appid), cmd="adb uninstall"
        )
        return "Success" in output
