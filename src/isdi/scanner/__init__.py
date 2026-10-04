#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Phone scanner module - handles Android and iOS device scanning.
- cli: Command path (adb for Android, pymobiledevice3 for iOS)
- run_command(): Returns subprocess.Popen object
- catch_err(): Takes Popen object, waits & returns string output
"""

import contextlib
import os
import json
import re
import shlex
import sqlite3
import subprocess
import logging
import time
from datetime import datetime
from typing import Optional, List, Tuple, Dict, Any

from isdi.config import get_config

from . import blocklist
from . import parse_dump
from .runcmd import catch_err, run_command

cfg = get_config()


def _jsonable(value):
    """Sets and tuples as lists, anything else (dates, ...) as text."""
    return list(value) if isinstance(value, (set, frozenset, tuple)) else str(value)


def _remove_dump_files(dumpf: str) -> None:
    """Delete a dump and any file derived from it (older versions cached the
    parse as .json next to the .txt)."""
    base = dumpf.rsplit(".", 1)[0]
    for f in (dumpf, raw_path(dumpf), base + ".txt", base + ".json"):
        try:
            os.remove(f)
        except FileNotFoundError:
            pass


def raw_path(dumpf: str) -> str:
    """Where the unredacted copy of an Android dump is written, only when an
    unredacted evidence copy was asked for. Deleted with the dump."""
    return dumpf + ".raw"


def purge_raw_dumps() -> int:
    """Delete every raw dump left in the dump directory (by a crash, or by
    a version that kept them). Returns how many files were removed."""
    removed = 0
    for name in os.listdir(cfg.DUMP_DIR):
        path = os.path.join(cfg.DUMP_DIR, name)
        if os.path.isfile(path):
            os.remove(path)
            removed += 1
    return removed


def _pseudonym(serial: str) -> str:
    """How logs name a device: a prefix of the stored HMAC, never the serial."""
    return "device-" + cfg.hmac_serial(serial)[:12] if serial else "device-?"


class AppScanner:
    """Base class for device scanners (Android/iOS)."""

    app_info_conn: Optional[sqlite3.Connection] = None

    def __init__(self, dev_type: str, cli: str):
        """
        Initialize scanner.

        Args:
            dev_type: 'android', 'ios', or 'test'
            cli: Command path (e.g., 'adb' or 'pymobiledevice3')
        """
        assert dev_type in cfg.DEV_SUPPORTED, f"Device type {dev_type} not supported"
        self.device_type: str = dev_type
        self.cli: str = cli
        self.ddump: Optional[parse_dump.PhoneDump] = None
        # Phones whose next dump also keeps the unredacted output, for an
        # unredacted evidence copy (Android only).
        self.unredacted_serials: set = set()

        # Initialize database connection once
        if AppScanner.app_info_conn is None:
            self._init_db()

    def _init_db(self) -> None:
        """Initialize SQLite connection for app info database."""
        try:
            db_path = cfg.APP_INFO_SQLITE_FILE.replace("sqlite:///", "")
            AppScanner.app_info_conn = sqlite3.connect(db_path, check_same_thread=False)
        except Exception as e:
            logging.error(f"Failed to connect to database: {e}")
            AppScanner.app_info_conn = None

    def devices(self) -> List[str]:
        """Return list of connected device serial numbers."""
        raise NotImplementedError()

    def get_apps(self, serialno: str) -> List[str]:
        """Return list of installed app package IDs."""
        raise NotImplementedError()

    def get_system_apps(self, serialno: str) -> List[str]:
        """Return list of system app package IDs (Android only)."""
        if not self.ddump:
            return []
        return self.ddump.system_apps()

    def get_offstore_apps(self, serialno: str) -> List[str]:
        """Return list of offstore/sideloaded app package IDs (Android only)."""
        if not self.ddump:
            return []
        return self.ddump.offstore_apps()

    def get_app_titles(self, serialno: str) -> Dict[str, str]:
        """Return dict of app package IDs and titles: {appId: title}."""
        return {}

    def dump_path(self, serial: str) -> str:
        """Where a device's raw dump is written while it is scanned. Dumps
        are deleted when the scan ends (discard_dump)."""
        fkind = "json" if self.device_type == "ios" else "txt"
        return os.path.join(
            cfg.DUMP_DIR, f"{cfg.hmac_serial(serial)}_{self.device_type}.{fkind}"
        )

    def _load_dump(self, serialno: str) -> Optional[parse_dump.PhoneDump]:
        """Load this phone's dump, taking it from the phone if needed."""
        dumpf = self.dump_path(serialno)

        # Re-dump if file is missing or suspiciously small (a header-only empty dump is ~600B)
        if not os.path.exists(dumpf) or os.path.getsize(dumpf) < 5000:
            self.ddump = None
            if not self._dump_phone(serialno):
                return None

        # The scanner is shared by all requests: only reuse the cached dump
        # if it is this phone's.
        if isinstance(self.ddump, parse_dump.PhoneDump) and self.ddump.dumpf == dumpf:
            return self.ddump

        try:
            if self.device_type == "android":
                self.ddump = parse_dump.AndroidDump(dumpf)
            elif self.device_type == "ios":
                self.ddump = parse_dump.IosDump(dumpf)
            return self.ddump
        except Exception as e:
            logging.error("Error loading the dump: %s", type(e).__name__)
            return None

    def dump_details(self, appids) -> Dict[str, Dict]:
        """What the current dump says about each app (install dates,
        permissions, data usage), as plain JSON-able data, to be stored
        with the scan in place of the dump itself."""
        details = {}
        for appid in appids:
            try:
                info = self.ddump.info(appid) if self.ddump else None
            except Exception as e:
                logging.warning("No dump details for an app: %s", type(e).__name__)
                info = None
            if info:
                details[appid] = json.loads(json.dumps(info, default=_jsonable))
        return details

    def discard_dump(self, serial: str) -> None:
        """Delete this phone's raw dump and forget the parsed copy. Called
        when a scan ends, saved or not: raw dumps are never kept."""
        if isinstance(self.ddump, parse_dump.PhoneDump) and self.ddump.dumpf == (
            self.dump_path(serial)
        ):
            self.ddump = None
        _remove_dump_files(self.dump_path(serial))

    def _dump_phone(self, serial: str) -> bool:
        """Dump device info by running shell script."""
        dumpf = self.dump_path(serial)
        os.makedirs(os.path.dirname(dumpf), exist_ok=True)

        _remove_dump_files(dumpf)
        self.ddump = None

        # Resolve script path
        script_path = cfg.SCRIPT_DIR / f"{self.device_type}_scan.sh"
        if not script_path.exists():
            logging.error(f"Script not found: {script_path}")
            return False

        logging.info("Dumping %s device %s...", self.device_type, _pseudonym(serial))

        # Run script: bash script.sh <serial> <output_file>
        p = run_command(
            "bash {script} {ser} {dump_file}",
            script=shlex.quote(str(script_path)),
            ser=shlex.quote(serial),
            dump_file=shlex.quote(dumpf),
            nowait=False,
        )

        # run_command() with nowait=False already waits and sets returncode
        if p.returncode != 0:
            logging.error(f"Dump failed with returncode {p.returncode}")
            return False

        logging.info(f"Dump completed successfully: {dumpf}")
        return os.path.exists(dumpf)

    def get_multiple_app_details(
        self, serialno: str, appids: List[str], stored: bool = False
    ) -> Dict[str, Tuple[Dict, Dict]]:
        """Get details for multiple apps at once, returning dict keyed by appId.
        With stored=True, serialno is the HMAC kept in the database."""

        def _process_app_row(appid: str, d: Dict) -> Tuple[Dict, Dict]:
            permissions = d.get("permissions")
            if isinstance(permissions, str):
                d["permissions"] = [
                    p.strip() for p in permissions.split(",") if p.strip()
                ]
            elif not permissions:
                d["permissions"] = []

            description = ""
            for col in (
                "description",
                "description_html",
                "descriptionhtml",
                "summary",
            ):
                if d.get(col):
                    description = str(d[col])
                    break
            if not description:
                description = next(
                    (
                        str(v)
                        for k, v in d.items()
                        if v and ("description" in k.lower() or "summary" in k.lower())
                    ),
                    "",
                )

            d["descriptionHTML"] = description
            d.setdefault("summary", d.get("title", ""))

            return d, device.get(appid, {})

        if not appids:
            return {}

        # What the phone's dump said, as saved with this phone's latest scan
        # (the dump itself is not kept). Saved-scan links already carry the
        # stored HMAC; live pages carry the serial.
        from isdi.scanner import db

        serial_hmac = serialno if stored else cfg.hmac_serial(serialno)
        scanid = db.get_most_recent_scan_id(serial_hmac)
        device = db.app_details_from_scan(scanid, appids) if scanid else {}

        if not AppScanner.app_info_conn:
            # No app metadata db: still show what the phone's dump says.
            return {appid: ({}, device.get(appid, {})) for appid in appids}

        conn = AppScanner.app_info_conn
        if conn.row_factory is None:
            conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        placeholders = ",".join("?" * len(appids))
        cur.execute(f"SELECT * FROM apps WHERE appid IN ({placeholders})", appids)

        details: Dict[str, Tuple[Dict, Dict]] = {}
        for row in cur.fetchall():
            d = dict(row)
            appid = d.get("appid") or d.get("appId") or ""
            if appid:
                details[appid] = _process_app_row(appid, d)

        # Apps missing from the metadata db (often exactly the sideloaded
        # ones) still get what the phone's dump says about them.
        for appid in appids:
            if appid not in details:
                details[appid] = ({}, device.get(appid, {}))
        return details

    def app_details(
        self, serialno: str, appid: str, stored: bool = False
    ) -> Tuple[Dict, Dict]:
        """Get detailed info for an app."""
        details = self.get_multiple_app_details(serialno, [appid], stored=stored)
        return details.get(appid, ({}, {}))

    def find_spyapps(self, serialno: str) -> Dict[str, Dict[str, Any]]:
        """
        Optimized find_spyapps for iOS that caches app titles lookup.

        The original isdi.scanner.find_spyapps calls get_app_titles() inside the loop
        for iOS, causing it to be called once per app. This optimized version
        pre-loads app titles once and reuses them.
        """
        installed_apps = self.get_apps(serialno)
        if not installed_apps:
            return {}

        # Get offstore and system apps (Android only - iOS returns empty)
        offstore = self.get_offstore_apps(serialno)
        system = self.get_system_apps(serialno)

        # Get app flags from blocklist
        flagged_apps = blocklist.app_title_and_flag(
            [{"appId": appid} for appid in installed_apps],
            offstore_apps=offstore,
            system_apps=system,
        )

        # Pre-load app titles once for iOS instead of in the loop
        app_titles_cache = None
        if self.device_type == "ios":
            try:
                app_titles_cache = self.get_app_titles(serialno)
            except Exception as e:
                logging.warning(f"Failed to get app titles cache: {e}")
                app_titles_cache = {}

        # Convert to dict with appId as key
        result = {}
        for app in flagged_apps:
            appid = app.get("appId", "")
            if not appid:
                continue
            title = app.get("title", "") or ""
            flags = app.get("flags", [])

            # Get app titles from database (Android)
            if self.device_type == "android" and AppScanner.app_info_conn and not title:
                try:
                    cursor = AppScanner.app_info_conn.cursor()
                    cursor.execute("SELECT title FROM apps WHERE appid = ?", (appid,))
                    row = cursor.fetchone()
                    if row:
                        title = row[0] or ""
                except Exception as e:
                    logging.error(f"Error getting title for {appid}: {e}")
            elif self.device_type == "ios" and app_titles_cache:
                # Use cached titles from iOS dump (loaded once, not in loop)
                title = app_titles_cache.get(appid, "") or title

            # ASCII encode/decode to handle special characters
            title = title.encode("ascii", errors="ignore").decode("ascii")

            # Classify and score
            score_val = blocklist.score(flags)
            class_val = blocklist.assign_class(flags)
            html_flags = blocklist.flag_str(flags)

            result[appid] = {
                "title": title,
                "flags": flags,
                "score": score_val,
                "class_": class_val,
                "html_flags": html_flags,
            }

        # Device owner detection (Android only — queries dpm list-owners on the live device)
        if self.device_type == "android" and hasattr(self, "get_device_owner_apps"):
            for appid in self.get_device_owner_apps(serialno):
                if appid in result:
                    flags = result[appid]["flags"]
                    if "device-owner" not in flags:
                        flags = flags + ["device-owner"]
                        result[appid] = {
                            **result[appid],
                            "flags": flags,
                            "score": blocklist.score(flags),
                            "class_": blocklist.assign_class(flags),
                            "html_flags": blocklist.flag_str(flags),
                        }

        # Sort by risk score descending, then by appId ascending
        sorted_apps = sorted(result.items(), key=lambda x: (-x[1]["score"], x[0]))

        # Return as dict keyed by appId
        return {appid: app_info for appid, app_info in sorted_apps}

    def device_info(self, serial: str) -> Tuple[str, Dict]:
        """Get human-readable device info string and dict."""
        return "", {}

    def isrooted(self, serial: str) -> Tuple[bool, List[str]]:
        """Check if device is rooted/jailbroken."""
        return False, []

    def uninstall(self, serial: str, appid: str) -> bool:
        """Uninstall an app (not implemented in base class)."""
        return False


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
        device_owner_apps = set()
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
        if not self.ddump:
            return {}
        titles_df = self.ddump.installed_apps_titles()
        # If it returns a DataFrame-like object, convert to dict
        # if hasattr(titles_df, 'to_dict'):
        #     # It's a DataFrame, convert to our dict format
        #     result = {}
        #     for appid, title in zip(titles_df.get('appId', []), titles_df.get('title', [])):
        #         result[appid] = title
        #     return result
        if isinstance(titles_df, dict):
            # Already a dict
            return titles_df
        else:
            # Try to iterate
            try:
                return {
                    item.get("appId"): item.get("title") for item in titles_df if item
                }
            except:
                return {}

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


class TestScanner(AppScanner):
    """Test scanner using mock data."""

    def __init__(self):
        super().__init__("android", "test")

    def devices(self) -> List[str]:
        return ["testdevice1", "testdevice2"]

    # What `isdi run --test` shows: ordinary apps, a dual-use app and a
    # stalkerware app from app-flags.csv.
    APPS = [
        "com.android.settings",
        "com.android.chrome",
        "com.google.android.gm",
        "com.whatsapp",
        "com.life360.android.safetymapd",
        "a.tck.lvmchi",
    ]

    def get_apps(self, serialno: str) -> List[str]:
        return list(self.APPS)

    def get_system_apps(self, serialno: str) -> List[str]:
        return self.get_apps(serialno)[:1]

    def get_offstore_apps(self, serialno: str) -> List[str]:
        return []

    def uninstall(self, serial: str, appid: str) -> bool:
        return True
