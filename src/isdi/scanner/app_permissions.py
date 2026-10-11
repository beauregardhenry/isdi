"""What the phone itself reports about an app's permissions, for the app
details page.

From the details ISDi keeps with each scan (the dump is not kept):
- Android: the runtime permissions (granted or not) and the install-time
  permissions, labelled with Android's own words (data/android_permissions.json);
- iPhone: the permissions in the app's settings, with the reason its
  developer gives.

The app details page used to list the Play Store's permission list under
"The app used N app permissions recently"; the store's list says what an
app may ask for, not what the phone gave it.
"""

import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List

from isdi.config import get_config

# Shown in the first rows of the page, in this order.
INFO_ROWS = [
    ("firstInstallTime", "Installed"),
    ("lastUpdateTime", "Last updated"),
    ("versionName", "Version"),
    ("App Version", "Version"),
    ("data_usage", "Data usage"),
    ("battery_usage", "Battery usage"),
    ("Install Date", "Install date"),
    ("Data Usage", "Data usage"),
    ("Battery Usage", "Battery usage"),
]


@lru_cache(maxsize=1)
def _labels() -> Dict[str, Dict[str, Any]]:
    path = Path(get_config().STATIC_DATA) / "android_permissions.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _android(info: dict) -> List[dict]:
    rows = []
    for kind in ("runtime permissions", "install permissions"):
        section = info.get(kind) or {}
        items = (
            section.items() if isinstance(section, dict) else ((s, "") for s in section)
        )
        for key, value in items:
            # The dump parser splits "android.permission.CAMERA: granted=true,
            # flags=[...]" at "=": the key ends in ": granted".
            name = str(key).split(":", 1)[0].strip()
            if not name:
                continue
            text = str(value).strip().lower()
            granted = (
                True
                if text.startswith("true")
                else False if text.startswith("false") else None
            )
            known = _labels().get(name, {})
            rows.append(
                {
                    "name": name,
                    "label": known.get("label")
                    or name.rsplit(".", 1)[-1].replace("_", " ").capitalize(),
                    "group": known.get("group", ""),
                    "sensitive": bool(known.get("dangerous")),
                    "granted": granted,
                    "kind": "runtime" if kind.startswith("runtime") else "install",
                    "reason": "",
                }
            )
    # Granted sensitive permissions first.
    rows.sort(
        key=lambda r: (
            not (r["sensitive"] and r["granted"]),
            not r["sensitive"],
            r["label"].lower(),
        )
    )
    return rows


def _ios_reason(reason: str) -> str:
    low = reason.lower()
    if "permission granted by system" in low:
        return "Granted by the system"
    if "infoplist.strings" in low or "undefined" in low:
        return "No reason given in the app"
    return reason


def _ios(info: dict) -> List[dict]:
    rows = []
    for item in info.get("permissions") or []:
        if not isinstance(item, (list, tuple)) or not item:
            continue
        name = str(item[0])
        reason = _ios_reason(str(item[1])) if len(item) > 1 else ""
        rows.append(
            {
                "name": name,
                "label": name,
                "group": "",
                "sensitive": False,
                "granted": None,
                "kind": "",
                "reason": reason,
            }
        )
    return rows


def from_phone(device: str, info: dict) -> List[dict]:
    if not isinstance(info, dict):
        return []
    return _ios(info) if device == "ios" else _android(info)


def _display(value: Any) -> str:
    if isinstance(value, dict):
        # Android's data usage: {"data_used": "3.00 MB",
        # "background_data_allowed": "not allowed"}.
        parts = []
        if value.get("data_used"):
            parts.append(str(value["data_used"]))
        if value.get("background_data_allowed"):
            parts.append(f"background data {value['background_data_allowed']}")
        return "; ".join(parts) or ", ".join(f"{k}: {v}" for k, v in value.items())
    return str(value)


def info_rows(info: dict) -> List[tuple]:
    """(label, value) for the facts the phone reported, without the
    permission lists and internal ids."""
    if not isinstance(info, dict):
        return []
    rows, seen = [], set()
    for key, label in INFO_ROWS:
        value = info.get(key)
        if value in (None, "", [], {}) or label in seen:
            continue
        seen.add(label)
        rows.append((label, _display(value)))
    return rows
