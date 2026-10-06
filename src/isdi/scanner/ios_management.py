"""Whether an iPhone is managed: supervised, or with configuration profiles
installed. Monitoring on iPhones is often done this way rather than with
an app, so the app list alone can look clean.

Read over USB through pymobiledevice3's MobileConfigService (the
com.apple.mobile.MCInstall lockdown service, as Apple Configurator uses).
Only reads: nothing is installed, removed or changed on the phone.

The response layout is from pymobiledevice3 and has not yet been checked
against a range of real iPhones, so parsing is lenient: anything not
recognised is left out, and a failure to read is reported as "could not
check", never as "not managed".
"""

import asyncio
import logging
from typing import Any, Dict, List, Optional

TIMEOUT = 10.0


def _text(value) -> str:
    return value.strip() if isinstance(value, str) else ""


def profiles_from(response: Any) -> List[Dict[str, Any]]:
    """The installed profiles in a GetProfileList response: name,
    organisation, description, identifier, and whether the profile says it
    cannot be removed by the phone's user."""
    if not isinstance(response, dict):
        return []
    metadata = response.get("ProfileMetadata")
    if not isinstance(metadata, dict):
        return []
    order = response.get("OrderedIdentifiers")
    ids = [i for i in order if i in metadata] if isinstance(order, list) else []
    ids += sorted(i for i in metadata if i not in ids)
    profiles = []
    for identifier in ids:
        meta = metadata.get(identifier)
        if not isinstance(meta, dict):
            meta = {}
        profiles.append(
            {
                "identifier": _text(identifier),
                "name": _text(meta.get("PayloadDisplayName")) or _text(identifier),
                "organization": _text(meta.get("PayloadOrganization")),
                "description": _text(meta.get("PayloadDescription")),
                "removal_disallowed": bool(meta.get("PayloadRemovalDisallowed")),
            }
        )
    return profiles


def supervision_from(cloud: Any) -> Dict[str, Any]:
    """Supervision and the managing organisation from a cloud
    configuration; None where the phone did not say."""
    if not isinstance(cloud, dict):
        return {"supervised": None, "organization": ""}
    supervised = cloud.get("IsSupervised")
    return {
        "supervised": supervised if isinstance(supervised, bool) else None,
        "organization": _text(cloud.get("OrganizationName")),
    }


async def _read(serial: str):
    from pymobiledevice3.lockdown import create_using_usbmux
    from pymobiledevice3.services.mobile_config import MobileConfigService

    from .root_check import _maybe_await

    client = await _maybe_await(create_using_usbmux(serial=serial))
    try:
        async with MobileConfigService(client) as service:
            profiles = await service.get_profile_list()
            cloud = await service.get_cloud_configuration()
    finally:
        await _maybe_await(client.close())
    return profiles, cloud


def check(serial: str) -> Dict[str, Any]:
    """{"checked", "supervised", "organization", "profiles", "error"}.
    "checked" is False when the phone could not be read (locked, not
    trusted, or an older or newer iOS that answers differently)."""
    result: Dict[str, Any] = {
        "checked": False,
        "supervised": None,
        "organization": "",
        "profiles": [],
        "error": None,
    }
    try:
        profiles, cloud = asyncio.run(asyncio.wait_for(_read(serial), TIMEOUT))
    except Exception as e:
        logging.info("iPhone management check failed (%s)", type(e).__name__)
        result["error"] = type(e).__name__
        return result
    result.update(supervision_from(cloud))
    result["profiles"] = profiles_from(profiles)
    result["checked"] = True
    return result


def is_managed(info: Optional[Dict[str, Any]]) -> bool:
    return bool(info and (info.get("supervised") or info.get("profiles")))


def summary_html(info: Optional[Dict[str, Any]]) -> str:
    """One line for the scan results; escaped, safe to mark |safe."""
    from markupsafe import escape

    if not info:
        return ""
    if not info.get("checked"):
        return (
            '<span class="text-muted">Could not check (unlock the phone and '
            "tap Trust, then scan again).</span>"
        )
    parts = []
    if info.get("supervised"):
        org = info.get("organization")
        parts.append(
            '<span class="text-warning">Supervised</span>'
            + (f" by {escape(org)}" if org else "")
        )
    elif info.get("supervised") is False:
        parts.append("Not supervised")
    profiles = info.get("profiles") or []
    if profiles:
        names = ", ".join(
            str(escape(p["name"]))
            + (f" ({escape(p['organization'])})" if p.get("organization") else "")
            for p in profiles
        )
        parts.append(
            f'<span class="text-warning">{len(profiles)} configuration '
            f"profile{'s' if len(profiles) != 1 else ''}</span>: {names}"
        )
    else:
        parts.append("no configuration profiles")
    return "; ".join(parts) + "."
