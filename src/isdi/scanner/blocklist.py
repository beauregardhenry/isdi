"""
This file have different ways to detect spyware apps add flags to them.
The csv file has two column appId, store, and flag
store: {'playstore', 'appstore', 'offstore'}
flag: {'dual-use', 'spyware', 'safe'}

Flags added to them are from the following four classes
1. "onstore-dual-use": onstore dual-use apps
2. "onstore-spyware": onstore apps which are clearly spyware based on our analysis
3. "offstore-spyware": offstore spyware apps
4. "regex-spy": Regex based spyware detection
5. "odds-ratio": Spyware based on high co-occurrence with other offstore-spyware
"""

import csv
import json
import re
from datetime import date
from pathlib import Path
from typing import Any, Dict, Optional

from isdi.config import get_config

config = get_config()

# Flags in app-flags.csv that the scanner uses. "stalkerware" is what
# scripts/get-stalkerware-indicators.py writes for every package in the
# AssoEchap stalkerware-indicators list.
LOADED_FLAGS = {"dual-use", "spyware", "stalkerware", "co-occurrence"}


def _load_app_flags(path) -> list:
    """Blocklist rows with a flag the scanner uses. A missing file raises:
    scanning without the blocklist would report stalkerware as harmless."""
    with open(path, encoding="latin1", newline="") as f:
        rows = [r for r in csv.DictReader(f) if r.get("flag") in LOADED_FLAGS]
    for r in rows:
        if r.get("title") in (None, "nan"):
            r["title"] = ""
    return rows


APP_FLAGS = _load_app_flags(config.APP_FLAGS_FILE)
# Recorded with each scan: which blocklist the results came from.
with open(config.APP_FLAGS_FILE, "rb") as _f:
    BLOCKLIST_SHA256 = __import__("hashlib").sha256(_f.read()).hexdigest()
# When the stalkerware list last changed (scripts/get-stalkerware-indicators.py
# writes it), or None for a copy without the file.
STALE_AFTER_DAYS = 120


def _load_updated(path) -> Optional[date]:
    try:
        with open(path, encoding="utf-8") as f:
            return date.fromisoformat(json.load(f)["updated"])
    except (OSError, ValueError, KeyError, TypeError):
        return None


BLOCKLIST_UPDATED = _load_updated(
    Path(config.APP_FLAGS_FILE).with_name("app-flags.meta.json")
)


def blocklist_status(today: Optional[date] = None) -> Dict[str, Any]:
    """The blocklist's date, its age in days and whether it is old enough
    that a newer ISDi release may carry a newer list."""
    if BLOCKLIST_UPDATED is None:
        return {"updated": None, "age_days": None, "stale": True}
    age = ((today or date.today()) - BLOCKLIST_UPDATED).days
    return {
        "updated": BLOCKLIST_UPDATED.isoformat(),
        "age_days": age,
        "stale": age > STALE_AFTER_DAYS,
    }


# appId -> row, built once (lookups happen for every app on every scan).
_FLAGS_BY_APPID = {r["appId"]: r for r in APP_FLAGS if r.get("appId")}

SPY_REGEX = {
    "pos": re.compile(r"(?i)(spy|track|keylog|cheating)"),
    "neg": re.compile(r"(?i)(anti.*(spy|track|keylog)|(spy|track|keylog).*remov[ea])"),
}


def dedup_app_flags(apps_list):
    """
    Takes list of dicts like [{"appId": "com.x", "title": "X", "flag": [...]}, ...]
    Returns deduplicated version by appId
    """
    result = {}
    for app in apps_list:
        appid = app.get("appId", "")
        if not appid:
            continue
        if appid not in result:
            result[appid] = {
                "appId": appid,
                "title": app.get("title", ""),
                "flags": [],
            }
        # Collect titles
        title = app.get("title", "")
        if result[appid]["title"] == "":
            result[appid]["title"] = title
        elif title and title != result[appid]["title"]:
            result[appid]["title"] = result[appid]["title"] + " -+- " + title
        # Collect flags. app_title_and_flag passes them as "flags"; reading
        # only "flag" silently dropped every app-flags.csv flag.
        flags = app.get("flags", app.get("flag", []))
        if isinstance(flags, str):
            flags = [flags] if flags else []
        elif isinstance(flags, list):
            flags = flags
        else:
            flags = []
        for flag in flags:
            if flag and flag not in result[appid]["flags"]:
                result[appid]["flags"].append(flag)

    return list(result.values())


def _regex_blocklist(app):
    # print("_regex_balcklist: {}".format(app))
    # return ['regex-spy'] if (SPY_REGEX['pos'].search(app) and not SPY_REGEX['neg'].search(app)) \
    #     else []
    return (
        SPY_REGEX["pos"].search(app) is not None
        and SPY_REGEX["neg"].search(app) is None
    )


SPECIAL_ACCESS_FLAGS = ("accessibility", "notification-access", "device-admin")


def score(flags):
    """The weights are completely arbitrary"""
    weight = {
        "onstore-dual-use": 0.8,
        "dual-use": 0.8,
        "onstore-spyware": 1.0,
        "offstore-spyware": 1.0,
        # Flags as stored in app-flags.csv (app_title_and_flag uses them as-is).
        "spyware": 1.0,
        "stalkerware": 1.0,
        "co-occurrence": 0.2,
        "offstore-app": 0.8,
        "regex-spy": 0.3,
        "odds-ratio": 0.2,
        "system-app": -0.1,
        "device-owner": 1.0,
        # Powers monitoring apps rely on; ordinary apps hold them too.
        "accessibility": 0.5,
        "notification-access": 0.4,
        "device-admin": 0.4,
    }
    return sum(map(lambda x: weight.get(x, 0.0), flags))


def assign_class(flags):
    """The Bootstrap class that colours an app's row by its score."""
    w = score(flags)
    norm_w = 0 if w <= 0 else 1 if w <= 0.3 else 2 if w <= 0.8 else 3
    _classes = ["", "alert-info", "alert-warning", "alert-primary"]
    return _classes[norm_w]


def flag_str(flags):
    """Returns a comma seperated strings"""

    def _add_class(flag):
        return (
            "primary"
            if "spyware" in flag or flag in ("stalkerware", "device-owner")
            else (
                "warning"
                if "dual-use" in flag or flag in SPECIAL_ACCESS_FLAGS
                else "info" if "spy" in flag else ""
            )
        )

    def _info(flag):
        return {
            "regex-spy": "This app's name or its app-id contain words like 'spy', 'track', etc.",
            "offstore-spyware": (
                "This app is a spyware app, distributed outside official applicate stores, e.g., "
                "Play Store or iTunes App Store"
            ),
            "spyware": "This app is a known spyware app.",
            "stalkerware": (
                "This app is listed as stalkerware in the Echap stalkerware-indicators "
                "database."
            ),
            "co-occurrence": "This app appears very frequently with other offstore-spyware apps.",
            "onstore-dual-use": "This app has a legitimate usecase, but can be harmful in certain situations.",
            "offstore-app": "This app is installed outside Play Store. It might be a preinstalled app too.",
            "dual-use": "This app has a legitimate usecase, but can be harmful in certain situations.",
            "system-app": "This app came preinstalled with the device.",
            "device-owner": "This app has device owner privilege, allowing it to have almost full control over the device.",
            "accessibility": (
                "This app is allowed to use accessibility services: it can read "
                "what is on the screen and act on it. Monitoring apps use this, "
                "as do many legitimate apps (password managers, screen readers)."
            ),
            "notification-access": (
                "This app is allowed to read every notification, including "
                "message previews. Monitoring apps use this, as do smartwatch "
                "and car apps."
            ),
            "device-admin": (
                "This app is a device administrator: it can lock or erase the "
                "phone and is harder to uninstall. Monitoring apps use this, as "
                "do work and find-my-phone apps."
            ),
        }.get(flag.lower(), flag)

    # If spyware <span class='text-danger'>{}</span>
    flags = [y.strip() for y in flags]
    return ",  ".join(
        '<span class="text-{0}"><abbr title="{1}">{2}</abbr></span>'.format(
            _add_class(flag), _info(flag), flag
        )
        for flag in flags
        if len(flag) > 0
    )


def app_title_and_flag(apps_list, offstore_apps=None, system_apps=None):
    """
    Gets app flags and title from app-flags data.

    Args:
        apps_list: List of dicts with 'appId' key, or a single dict
        offstore_apps: List of offstore app IDs
        system_apps: List of system app IDs

    Returns:
        List of dicts with keys: appId, title, flags
    """
    offstore_apps = offstore_apps or []
    system_apps = system_apps or []

    # Convert input to list of dicts
    if isinstance(apps_list, dict):
        apps_data = [apps_list]
    else:
        apps_data = list(apps_list) if hasattr(apps_list, "__iter__") else [apps_list]

    flags_dict = _FLAGS_BY_APPID

    # Build result: merge with APP_FLAGS
    result = {}
    for app in apps_data:
        appid = app.get("appId", "")
        if not appid:
            continue

        # Get flags from APP_FLAGS
        flag_data = flags_dict.get(appid, {})
        title = flag_data.get("title", "") or app.get("title", "")
        flag_str = flag_data.get("flag", "")
        flags = [flag_str] if flag_str else []

        if appid not in result:
            result[appid] = {
                "appId": appid,
                "title": title,
                "flags": flags,
            }

    # Convert to list for dedup
    apps_list_for_dedup = list(result.values())
    deduped = dedup_app_flags(apps_list_for_dedup)

    # Now process the deduped list
    result_dict = {app["appId"]: app for app in deduped}

    # Add offstore-app flag
    for appid in offstore_apps:
        if appid in result_dict:
            if "offstore-app" not in result_dict[appid]["flags"]:
                result_dict[appid]["flags"].append("offstore-app")

    # Add system-app flag
    for appid in system_apps:
        if appid in result_dict:
            if "system-app" not in result_dict[appid]["flags"]:
                result_dict[appid]["flags"].append("system-app")

    # Regex-based flagging
    for appid, app_data in result_dict.items():
        is_spy = _regex_blocklist(appid) or _regex_blocklist(app_data.get("title", ""))
        if is_spy and "regex-spy" not in app_data["flags"]:
            app_data["flags"].append("regex-spy")

    # Return as list
    return list(result_dict.values())


if __name__ == "__main__":
    apps = [{"appId": "com.TrackView"}, {"appId": "com.apple.mobileme.fmf1"}]
    print(app_title_and_flag(apps, system_apps=["com.apple.mobileme.fmf1"]))
