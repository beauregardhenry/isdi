"""`isdi field-test`: run every check on a connected **test** phone and report
what each part of ISDi recognised, so the parsers can be confirmed or fixed
against real phones without anyone sending phone data.

The report holds structure, not content: tool versions, which parts of the
phone's output were present and how large, how many entries each parser
recognised, and the names of the fields in Apple's answers (protocol keys,
never their values). It never holds app ids, app or account names, profile
names, serial numbers or email addresses. Before it is returned,
assert_private() checks that none of the phone's app ids or its serial
appear in it.

The dump is deleted when the test ends, as after a scan, and nothing is
written to the database or the audit log.
"""

import asyncio
import json
import platform
import re
from collections import Counter
from importlib import metadata
from typing import Any, Dict, Iterable, List, Optional

from isdi import __version__

PowerCounts = Dict[str, int]


class NotPrivate(AssertionError):
    """The report would contain something from the phone; it is not kept."""


def _version(package: str) -> Optional[str]:
    try:
        return metadata.version(package)
    except metadata.PackageNotFoundError:
        return None


def environment() -> Dict[str, Any]:
    from isdi.scanner.pmd3_wrapper import is_termux

    return {
        "isdi": __version__,
        "python": platform.python_version(),
        "system": f"{platform.system()} {platform.release()}",
        "termux": is_termux(),
        "pymobiledevice3": _version("pymobiledevice3"),
    }


def _adb_version(sc) -> Optional[str]:
    from isdi.scanner.runcmd import catch_err

    try:
        out = catch_err(sc.run_tool("version"), cmd="adb version")
        lines = out.strip().splitlines()
        return lines[0].strip() if lines else None
    except Exception as e:
        return f"unavailable ({type(e).__name__})"


def _root_checks(reasons: Iterable[str]) -> List[str]:
    """The names of the root checks that fired, not their output."""
    names = []
    for reason in reasons:
        m = re.search(r"Failed rootcheck '([^']+)'", str(reason))
        names.append(m.group(1) if m else "other")
    return sorted(set(names))


def android(sc, serial: str) -> Dict[str, Any]:
    """Run the Android checks on the phone `serial` (scanner `sc`)."""
    from isdi.scanner import parse_dump

    report: Dict[str, Any] = {"device_type": "android", "adb": _adb_version(sc)}
    _, info = sc.device_info(serial)
    report["device"] = {
        "manufacturer": info.get("brand"),
        "model": info.get("model"),
        "android_version": info.get("version"),
    }
    secrets = [serial]
    try:
        apps = sc.get_apps(serial)
        dump = sc.ddump
        report["dump"] = {"made": dump is not None}
        if dump is None:
            return report
        secrets += apps
        text = open(sc.dump_path(serial), errors="replace").read()
        sections = parse_dump._sections(text)
        report["dump"].update(
            {
                "bytes": len(text.encode()),
                # Section name -> size: shows which dumpsys outputs came back.
                "sections": {
                    name: len(body) for name, body in sorted(sections.items())
                },
            }
        )
        secure = sections.get("secure", "")
        settings: Dict[str, Any] = {}
        for key in parse_dump.SPECIAL_ACCESS_SETTINGS:
            line = next(
                (l for l in secure.splitlines() if l.strip().startswith(key + "=")),
                None,
            )
            value = line.split("=", 1)[1] if line else ""
            settings[key] = {
                "present": line is not None,
                "entries": len([c for c in value.split(":") if "/" in c]),
            }
        policy = sections.get("device_policy", "")
        powers: Counter = Counter()
        for granted in dump.special_access.values():
            powers.update(granted)
        report["special_access"] = {
            "secure_settings": settings,
            "device_policy_section": bool(policy.strip()),
            "enabled_device_admins_heading": "Enabled Device Admins" in policy,
            "apps_per_power": dict(sorted(powers.items())),
        }
        report["apps"] = {
            "installed": len(apps),
            "system": len(dump.system_apps()),
            "off_store": len(dump.offstore_apps()),
            "device_owner": len(sc.get_device_owner_apps(serial)),
        }
        rooted, reasons = sc.isrooted(serial)
        report["root_check"] = {
            "rooted": rooted,
            "checks_fired": _root_checks(reasons),
        }
    finally:
        sc.discard_dump(serial)
    return assert_private(report, secrets)


def _title_sources(apps: List[dict]) -> PowerCounts:
    out: Counter = Counter()
    for app in apps:
        for key in ("CFBundleDisplayName", "CFBundleName", "CFBundleExecutable"):
            if isinstance(app.get(key), str) and app[key].strip():
                out[key] += 1
                break
        else:
            out["none"] += 1
    return dict(sorted(out.items()))


def _keys(value: Any) -> Optional[List[str]]:
    return sorted(value) if isinstance(value, dict) else None


def ios(sc, serial: str) -> Dict[str, Any]:
    """Run the iPhone checks on the phone `serial` (scanner `sc`)."""
    from isdi.scanner import ios_management, parse_dump, root_check

    report: Dict[str, Any] = {"device_type": "ios"}
    secrets = [serial]
    try:
        name, info = sc.device_info(serial)
        dump = sc.ddump if isinstance(sc.ddump, parse_dump.IosDump) else None
        report["dump"] = {"made": dump is not None}
        if dump is None:
            return report
        apps = dump.installed_apps()
        secrets += apps
        report["device"] = {
            "model": info.get("model"),
            "ios_version": info.get("version"),
            "model_known": bool(info.get("model"))
            and dump.deviceinfo.get("ProductType", "") in dump.model_make_map,
        }
        report["apps"] = {
            "installed": len(apps),
            "system": len(dump.system_apps()),
            "name_taken_from": _title_sources(dump.appinfo),
            "app_fields_seen": sorted(
                {k for app in dump.appinfo for k in app if k.startswith("CF")}
            ),
        }
        # The jailbreak check's USB signal, with why it failed if it did.
        try:
            afc2 = root_check._afc2_service_opens(serial)
            report["afc2"] = {"opened": bool(afc2)}
        except Exception as e:
            report["afc2"] = {"opened": False, "error": type(e).__name__}
        rooted, reasons = sc.isrooted(serial)
        report["jailbreak_check"] = {
            "jailbroken": rooted,
            "checks_fired": _root_checks(reasons),
        }
        # Supervision and profiles: the shape of Apple's answers.
        try:
            profiles, cloud = asyncio.run(
                asyncio.wait_for(ios_management._read(serial), ios_management.TIMEOUT)
            )
            metadata_ = (
                profiles.get("ProfileMetadata") if isinstance(profiles, dict) else None
            )
            report["management"] = {
                "read": True,
                "profile_list_keys": _keys(profiles),
                "profiles": len(metadata_) if isinstance(metadata_, dict) else None,
                "profile_metadata_keys": sorted(
                    {
                        k
                        for m in (metadata_ or {}).values()
                        if isinstance(m, dict)
                        for k in m
                    }
                ),
                "cloud_configuration_keys": _keys(cloud),
                "parsed": {
                    k: v
                    for k, v in ios_management.supervision_from(cloud).items()
                    if k == "supervised"
                },
            }
        except Exception as e:
            report["management"] = {"read": False, "error": type(e).__name__}
    finally:
        sc.discard_dump(serial)
    return assert_private(report, secrets)


def assert_private(report: Dict[str, Any], secrets: Iterable[str]) -> Dict[str, Any]:
    """Refuse a report that contains the serial or an app id."""
    text = json.dumps(report)
    leaked = [s for s in secrets if s and len(s) > 3 and s in text]
    if leaked:
        raise NotPrivate(
            f"the report would contain {len(leaked)} identifier(s) from the phone"
        )
    return report


def render(report: Dict[str, Any]) -> str:
    """The report as text to read and send: JSON, with a header."""
    header = (
        "ISDi field test. Made on a test phone; contains no app ids, names, "
        "serial numbers or account details.\n"
    )
    return header + json.dumps(report, indent=2, sort_keys=False) + "\n"


def run(device: str, serial: Optional[str] = None) -> Dict[str, Any]:
    """Field-test the first connected phone of `device` (or `serial`)."""
    from isdi.scanner import AndroidScanner, IosScanner

    sc = AndroidScanner() if device == "android" else IosScanner()
    report: Dict[str, Any] = {"environment": environment()}
    connected = sc.devices()
    report["connected_devices"] = len(connected)
    if serial is None:
        if not connected:
            report["result"] = "no phone found"
            return report
        serial = connected[0]
    elif serial not in connected:
        report["result"] = "that phone is not connected"
        return report
    report.update(android(sc, serial) if device == "android" else ios(sc, serial))
    report["result"] = "done"
    return assert_private(report, [serial])


__all__ = ["run", "render", "environment", "assert_private", "NotPrivate"]
