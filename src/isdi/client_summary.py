"""A plain-language summary of one scan, for the client, in English or
Spanish.

Shown on screen; printed only if the client wants a copy (a paper report
found by the person monitoring them could put them at risk). The wording
is neutral: the page's title and headings do not mention abuse or
spyware, and nothing says who might be responsible.

Built from the saved scan each time it is opened; nothing new is stored.

The Spanish text is a translation that has not yet been reviewed by a
native speaker who works with clients; review it before relying on it.
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

LANGUAGES = {"en": "English", "es": "Español"}

TEXT: Dict[str, Dict[str, Any]] = {
    "en": {
        "page_title": "Phone check summary",
        "the_phone": "the phone",
        "checked_on": "checked",
        "staff_note": "<strong>For staff:</strong> show this on screen. Print it "
        "only if the client wants a copy and has somewhere safe to keep it: a "
        "paper copy found by someone else could put them at risk.",
        "print": "Print",
        "language": "Language",
        "h_checked": "What we checked",
        "checked_apps": "The apps installed on {phone} ({n} in all).",
        "checked_root_ios": "Whether the phone's built-in protections have been "
        "removed (jailbreaking).",
        "checked_root_android": "Whether the phone's built-in protections have "
        "been removed (rooting).",
        "checked_managed": "Whether the phone is managed by an organisation "
        "(supervision or configuration profiles).",
        "management_unchecked": "We could not check whether this phone is managed "
        "by an organisation. This can be checked again with the phone unlocked.",
        "h_found": "What we found",
        "nothing_found": "We did not find any apps known to be used for "
        "monitoring, or other signs we check for.",
        "known_title": "Apps known to be used for monitoring",
        "known_meaning": "These apps are on public lists of apps that can "
        "secretly share a phone's messages, location or other activity with "
        "someone else.",
        "rooted_title": "The phone's protections appear to have been removed",
        "rooted_meaning": "This lets apps do things a phone normally does not "
        "allow, including hidden monitoring. It is sometimes done by the "
        "phone's owner on purpose.",
        "managed_title": "The phone is managed",
        "supervised": "The phone is supervised.",
        "supervised_by": "The phone is supervised by {org}.",
        "managed_meaning": "Whoever manages the phone can change its settings and "
        "may be able to see some of its activity. Work and school phones are "
        "often managed for ordinary reasons.",
        "powers_title": "Apps with powerful permissions",
        "powers_meaning": "These apps can read the screen, read notifications, or "
        "control the phone. Many everyday apps need this; it is worth checking "
        "that you recognise each one.",
        "dual_title": "Apps that can share location or activity",
        "dual_meaning": "These apps have everyday uses, such as finding a lost "
        "phone or family location sharing, but can also be used to keep track "
        "of someone.",
        "h_limits": "What this check cannot tell you",
        "limits": [
            "It looks for known signs. A new or rare app may not be recognised.",
            "Someone who knows your passwords can see a lot from your online "
            "accounts (email, Apple ID or Google account, social media) without "
            "any app on the phone.",
            "A finding is not proof that someone is watching you, and finding "
            "nothing is not proof that no one is.",
        ],
        "h_next": "Before changing anything",
        "next": [
            "Talk through a safety plan with your advocate first.",
            "Removing an app or profile can alert the person who set it up, and "
            "removes information that may matter later, for example in court. A "
            "record can be kept before anything is removed.",
            "If you decide to change passwords, do it from a device you trust, "
            "and turn on two-step verification where you can.",
        ],
    },
    "es": {
        "page_title": "Resumen de la revisión del teléfono",
        "the_phone": "el teléfono",
        "checked_on": "revisado el",
        "staff_note": "<strong>Para el personal:</strong> muestre esto en la "
        "pantalla. Imprímalo solo si la persona quiere una copia y tiene un "
        "lugar seguro para guardarla: una copia en papel encontrada por otra "
        "persona podría poner en riesgo su seguridad.",
        "print": "Imprimir",
        "language": "Idioma",
        "h_checked": "Lo que revisamos",
        "checked_apps": "Las aplicaciones instaladas en {phone} ({n} en total).",
        "checked_root_ios": "Si se quitaron las protecciones propias del teléfono "
        "(jailbreak).",
        "checked_root_android": "Si se quitaron las protecciones propias del "
        "teléfono (root).",
        "checked_managed": "Si una organización administra el teléfono "
        "(supervisión o perfiles de configuración).",
        "management_unchecked": "No pudimos revisar si una organización administra "
        "este teléfono. Se puede revisar de nuevo con el teléfono desbloqueado.",
        "h_found": "Lo que encontramos",
        "nothing_found": "No encontramos aplicaciones conocidas por usarse para "
        "vigilar a alguien, ni otras señales que revisamos.",
        "known_title": "Aplicaciones conocidas por usarse para vigilar",
        "known_meaning": "Estas aplicaciones aparecen en listas públicas de "
        "aplicaciones que pueden compartir en secreto los mensajes, la ubicación "
        "u otra actividad del teléfono con otra persona.",
        "rooted_title": "Parece que se quitaron las protecciones del teléfono",
        "rooted_meaning": "Esto permite que las aplicaciones hagan cosas que un "
        "teléfono normalmente no permite, incluida la vigilancia oculta. A veces "
        "la persona dueña del teléfono lo hace a propósito.",
        "managed_title": "El teléfono está administrado",
        "supervised": "El teléfono está supervisado.",
        "supervised_by": "El teléfono está supervisado por {org}.",
        "managed_meaning": "Quien administra el teléfono puede cambiar su "
        "configuración y quizá ver parte de su actividad. Los teléfonos del "
        "trabajo o de la escuela muchas veces se administran por razones comunes.",
        "powers_title": "Aplicaciones con permisos amplios",
        "powers_meaning": "Estas aplicaciones pueden leer la pantalla, leer las "
        "notificaciones o controlar el teléfono. Muchas aplicaciones comunes lo "
        "necesitan; conviene revisar que reconozca cada una.",
        "dual_title": "Aplicaciones que pueden compartir la ubicación o la "
        "actividad",
        "dual_meaning": "Estas aplicaciones tienen usos cotidianos, como encontrar "
        "un teléfono perdido o compartir la ubicación en familia, pero también "
        "pueden usarse para seguirle la pista a alguien.",
        "h_limits": "Lo que esta revisión no puede decirle",
        "limits": [
            "Busca señales conocidas. Es posible que no reconozca una aplicación "
            "nueva o poco común.",
            "Alguien que conoce sus contraseñas puede ver mucho desde sus cuentas "
            "en línea (correo, Apple ID o cuenta de Google, redes sociales) sin "
            "ninguna aplicación en el teléfono.",
            "Un hallazgo no prueba que alguien esté vigilando su teléfono, y "
            "no encontrar nada no prueba que nadie lo haga.",
        ],
        "h_next": "Antes de cambiar algo",
        "next": [
            "Primero hable con su intercesor(a) sobre un plan de seguridad.",
            "Quitar una aplicación o un perfil puede alertar a la persona que lo "
            "instaló y borra información que podría importar más adelante, por "
            "ejemplo en un tribunal. Se puede guardar un registro antes de quitar "
            "algo.",
            "Si decide cambiar sus contraseñas, hágalo desde un dispositivo de "
            "confianza y active la verificación en dos pasos cuando pueda.",
        ],
    },
}


def language(requested: Any) -> str:
    """A supported language code; English for anything else."""
    return requested if requested in TEXT else "en"


def _name(appid: str, title: str) -> str:
    return f"{title} ({appid})" if title and title != appid else appid


def _group(apps: Dict[str, Dict[str, Any]], flags: set) -> List[str]:
    return [
        _name(appid, info.get("title", ""))
        for appid, info in apps.items()
        if flags & set(info.get("flags", []))
    ]


def build(
    scan: Dict[str, Any], apps: Dict[str, Dict[str, Any]], lang: str = "en"
) -> Dict[str, Any]:
    """What the summary page shows: what was checked, what was found (each
    finding with what it means), and the limits of the check, plus the
    page's fixed text ("t") in the chosen language.

    `apps` maps app id -> {"title", "flags"} as on the results page."""
    lang = language(lang)
    t = TEXT[lang]
    device = scan.get("device")
    phone = (
        " ".join(
            p
            for p in (scan.get("device_manufacturer"), scan.get("device_model"))
            if p and not str(p).startswith("<")
        )
        or t["the_phone"]
    )
    checked = [
        t["checked_apps"].format(phone=phone, n=len(apps)),
        t["checked_root_ios" if device == "ios" else "checked_root_android"],
    ]
    management = None
    if device == "ios":
        try:
            management = json.loads(scan.get("device_management") or "null")
        except (json.JSONDecodeError, TypeError):
            management = None
        checked.append(t["checked_managed"])

    def finding(key: str, items: List[str]) -> Dict[str, Any]:
        return {
            "title": t[f"{key}_title"],
            "items": items,
            "meaning": t[f"{key}_meaning"],
        }

    findings = []
    known = _group(apps, KNOWN_MONITORING)
    if known:
        findings.append(finding("known", known))
    if scan.get("is_rooted") in (True, 1):
        findings.append(finding("rooted", []))
    if isinstance(management, dict) and ios_management.is_managed(management):
        items = []
        if management.get("supervised"):
            org = management.get("organization")
            items.append(t["supervised_by"].format(org=org) if org else t["supervised"])
        items += [
            p["name"] + (f" ({p['organization']})" if p.get("organization") else "")
            for p in management.get("profiles") or []
        ]
        findings.append(finding("managed", items))
    powers = _group(apps, POWERS)
    if powers:
        findings.append(finding("powers", powers))
    dual = _group(apps, DUAL_USE)
    if dual:
        findings.append(finding("dual", dual))

    return {
        "lang": lang,
        "t": t,
        "phone": phone,
        "checked": checked,
        "management_unchecked": isinstance(management, dict)
        and not management.get("checked"),
        "findings": findings,
    }
