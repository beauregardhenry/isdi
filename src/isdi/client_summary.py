"""A plain-language summary of one scan, for the client.

Shown on screen; printed only if the client wants a copy (a paper report
found by the person monitoring them could put them at risk). The wording
is neutral: the page's title and headings do not mention abuse or
spyware, and nothing says who might be responsible.

Built from the saved scan each time it is opened; nothing new is stored.
"""

import json
from typing import Any, Dict, List

from isdi.scanner import ios_management

KNOWN_MONITORING = {
    "spyware",
    "stalkerware",
    "offstore-spyware",
    "onstore-spyware",
}
DUAL_USE = {"dual-use", "onstore-dual-use"}
POWERS = {"accessibility", "notification-access", "device-admin", "device-owner"}


def _name(appid: str, title: str) -> str:
    return f"{title} ({appid})" if title and title != appid else appid


def _group(apps: Dict[str, Dict[str, Any]], flags: set) -> List[str]:
    return [
        _name(appid, info.get("title", ""))
        for appid, info in apps.items()
        if flags & set(info.get("flags", []))
    ]


def build(scan: Dict[str, Any], apps: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """What the summary page shows: what was checked, what was found (each
    finding with what it means), and the limits of the check.

    `apps` maps app id -> {"title", "flags"} as on the results page."""
    device = scan.get("device")
    phone = (
        " ".join(
            p
            for p in (scan.get("device_manufacturer"), scan.get("device_model"))
            if p and not str(p).startswith("<")
        )
        or "the phone"
    )
    checked = [
        f"The apps installed on {phone} ({len(apps)} in all).",
        "Whether the phone's built-in protections have been removed "
        + ("(jailbreaking)." if device == "ios" else "(rooting)."),
    ]
    management = None
    if device == "ios":
        try:
            management = json.loads(scan.get("device_management") or "null")
        except (json.JSONDecodeError, TypeError):
            management = None
        checked.append(
            "Whether the phone is managed by an organisation (supervision or "
            "configuration profiles)."
        )

    findings = []
    known = _group(apps, KNOWN_MONITORING)
    if known:
        findings.append(
            {
                "title": "Apps known to be used for monitoring",
                "items": known,
                "meaning": "These apps are on public lists of apps that can "
                "secretly share a phone's messages, location or other "
                "activity with someone else.",
            }
        )
    if scan.get("is_rooted") in (True, 1):
        findings.append(
            {
                "title": "The phone's protections appear to have been removed",
                "items": [],
                "meaning": "This lets apps do things a phone normally does "
                "not allow, including hidden monitoring. It is sometimes "
                "done by the phone's owner on purpose.",
            }
        )
    if isinstance(management, dict) and ios_management.is_managed(management):
        items = []
        if management.get("supervised"):
            org = management.get("organization")
            items.append("The phone is supervised" + (f" by {org}." if org else "."))
        items += [
            p["name"] + (f" ({p['organization']})" if p.get("organization") else "")
            for p in management.get("profiles") or []
        ]
        findings.append(
            {
                "title": "The phone is managed",
                "items": items,
                "meaning": "Whoever manages the phone can change its settings "
                "and may be able to see some of its activity. Work and school "
                "phones are often managed for ordinary reasons.",
            }
        )
    powers = _group(apps, POWERS)
    if powers:
        findings.append(
            {
                "title": "Apps with powerful permissions",
                "items": powers,
                "meaning": "These apps can read the screen, read "
                "notifications, or control the phone. Many everyday apps "
                "need this; it is worth checking that you recognise each one.",
            }
        )
    dual = _group(apps, DUAL_USE)
    if dual:
        findings.append(
            {
                "title": "Apps that can share location or activity",
                "items": dual,
                "meaning": "These apps have everyday uses, such as finding a "
                "lost phone or family location sharing, but can also be used "
                "to keep track of someone.",
            }
        )

    return {
        "phone": phone,
        "checked": checked,
        "management_unchecked": isinstance(management, dict)
        and not management.get("checked"),
        "findings": findings,
    }
