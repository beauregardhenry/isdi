"""Accessibility basics the axe-core audit of the web interface checked
(WCAG 2.1 AA), kept from regressing; and the client summary in Spanish."""

import json
import re
from pathlib import Path

import pytest

from isdi import audit, client_summary
from isdi.scanner import db

TEMPLATES = Path(__file__).resolve().parent.parent / "src/isdi/web/templates"


@pytest.mark.parametrize("template", sorted(p.name for p in TEMPLATES.glob("*.html")))
def test_images_have_alt_text_and_real_paths(template):
    html = (TEMPLATES / template).read_text()
    for img in re.findall(r"<img\b[^>]*>", html):
        assert "alt=" in img, img
    assert "/webstatic/" not in html  # no such route: those images were 404s


@pytest.mark.parametrize(
    "image", ["apple.resized.png", "android.resiz.png", "usb_android.resized.png"]
)
def test_instruction_images_are_served(client, image):
    assert client.get(f"/static/images/{image}").status_code == 200


@pytest.mark.parametrize(
    "path", ["/", "/instruction", "/privacy", "/form/", "/account/password"]
)
def test_pages_have_landmarks_and_one_h1(client, path):
    html = client.get(path).get_data(as_text=True)
    assert '<html lang="en">' in html
    assert 'href="#main"' in html and '<main id="main"' in html
    assert len(re.findall(r"<h1\b", html)) == 1, path


def test_status_messages_are_announced(client):
    html = client.get("/").get_data(as_text=True)
    assert (
        'id="msg" class="alert alert-primary" role="status" aria-live="polite"' in html
    )
    assert re.search(r'<label class="sr-only" for="device_owner">', html)


def test_the_spanish_text_has_every_key():
    en, es = client_summary.TEXT["en"], client_summary.TEXT["es"]
    assert set(en) == set(es)
    for key in en:
        assert type(en[key]) is type(es[key]), key
        if isinstance(en[key], list):
            assert len(en[key]) == len(es[key]), key
    for key in ("checked_apps", "supervised_by"):
        assert set(re.findall(r"{\w+}", en[key])) == set(re.findall(r"{\w+}", es[key]))


@pytest.mark.parametrize("requested, lang", [("es", "es"), ("fr", "en"), (None, "en")])
def test_language_choice(requested, lang):
    assert client_summary.language(requested) == lang


def test_summary_in_spanish():
    scan = {
        "device": "ios",
        "device_manufacturer": "<Unknown>",
        "is_rooted": True,
        "device_management": json.dumps(
            {"checked": True, "supervised": True, "organization": "", "profiles": []}
        ),
    }
    s = client_summary.build(
        scan, {"com.spy": {"title": "", "flags": ["spyware"]}}, "es"
    )
    assert s["lang"] == "es" and s["phone"] == "el teléfono"
    assert s["checked"][0] == "Las aplicaciones instaladas en el teléfono (1 en total)."
    assert [f["title"] for f in s["findings"]] == [
        "Aplicaciones conocidas por usarse para vigilar",
        "Parece que se quitaron las protecciones del teléfono",
        "El teléfono está administrado",
    ]
    assert s["findings"][2]["items"] == ["El teléfono está supervisado."]


def test_summary_page_in_spanish(app, client):
    with app.app_context():
        scanid = db.create_scan(
            {
                "clientid": "20260101_001",
                "serial": "s",
                "device": "android",
                "device_model": "Pixel",
                "device_version": "14",
                "device_manufacturer": "Google",
                "last_full_charge": "",
                "device_primary_user": "N",
                "is_rooted": False,
                "rooted_reasons": "[]",
            }
        )
    page = client.get(f"/scan/{scanid}/client-summary?lang=es").get_data(as_text=True)
    assert '<html lang="es">' in page
    assert "<title>Resumen de la revisión del teléfono</title>" in page
    assert "Lo que encontramos" in page and "What we found" not in page
    assert f'href="/scan/{scanid}/client-summary?lang=en"' in page
    with app.app_context():
        viewed = [e for e in audit.entries() if e["action"] == "client_summary_viewed"]
    assert viewed[-1]["details"] == {"lang": "es"}

    english = client.get(f"/scan/{scanid}/client-summary?lang=xx")
    assert '<html lang="en">' in english.get_data(as_text=True)


# --- second axe-core pass (2026-11-01): consultation pages and contrast -----------

CONSULTATION_PAGES = [
    "/consultation",
    "/consultation/questionnaire",
    "/consultation/accounts/new",
    "/consultation/devices/add",
    "/consultation/devices/manual",
    "/consultation/screenshots",
]


@pytest.mark.parametrize("path", CONSULTATION_PAGES)
def test_consultation_pages_have_landmarks_and_one_h1(client, path):
    html = client.get(path).get_data(as_text=True)
    assert '<html lang="en">' in html
    assert 'href="#main"' in html and '<main id="main"' in html
    assert len(re.findall(r"<h1\b", html)) == 1, path


def test_the_report_is_in_a_main_landmark(client):
    """axe: everything on the printable report sat outside any landmark."""
    for query in ("", "?copy=takehome", "?copy=takehome&lang=es"):
        html = client.get("/consultation/report" + query).get_data(as_text=True)
        assert re.search(r"<html lang=\"(en|es)\">", html)
        body = html.split("<body>", 1)[1]
        assert body.lstrip().startswith("<main") and "</main>" in body, query


STYLE = Path(__file__).resolve().parent.parent / "src/isdi/web/static/style.css"
# The backgrounds text sits on: white, the page (#f5f7fa), and the row
# colours of scan results (alert/table primary, warning, danger, success).
BACKGROUNDS = ["#ffffff", "#f5f7fa", "#cce5ff", "#fff3cd", "#f8d7da", "#d4edda"]


def _luminance(hex_colour):
    c = [int(hex_colour.lstrip("#")[i : i + 2], 16) / 255 for i in (0, 2, 4)]
    c = [x / 12.92 if x <= 0.03928 else ((x + 0.055) / 1.055) ** 2.4 for x in c]
    return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2]


def _contrast(a, b):
    hi, lo = sorted([_luminance(a), _luminance(b)], reverse=True)
    return (hi + 0.05) / (lo + 0.05)


def _colour_of(selector):
    """The colour style.css gives `selector` (the last rule that sets it)."""
    css = re.sub(r"/\*.*?\*/", "", STYLE.read_text(), flags=re.S)
    found = None
    for selectors, body in re.findall(r"([^{}]+)\{([^{}]*)\}", css):
        if selector in [s.strip() for s in selectors.split(",")]:
            m = re.search(r"(?<![-\w])color:\s*(#[0-9a-fA-F]{6})", body)
            if m:
                found = m.group(1)
    assert found, f"style.css sets no colour for {selector}"
    return found


@pytest.mark.parametrize(
    "selector",
    [
        ".btn-outline-secondary",
        ".btn-outline-primary",
        ".btn-outline-danger",
        ".text-warning",
        ".text-muted",
        ".text-danger",
        ".text-primary",
    ],
)
def test_text_colours_meet_aa_on_every_background(selector):
    colour = _colour_of(selector)
    for bg in BACKGROUNDS:
        assert _contrast(colour, bg) >= 4.5, (selector, colour, bg)


@pytest.mark.parametrize(
    "selector",
    [".btn-outline-secondary", ".btn-outline-primary", ".btn-outline-danger"],
)
def test_outline_buttons_keep_contrast_when_filled(selector):
    """On hover and focus Bootstrap fills the button with its colour and
    turns the text white."""
    assert _contrast(_colour_of(selector), "#ffffff") >= 4.5


@pytest.mark.parametrize("template", sorted(p.name for p in TEMPLATES.rglob("*.html")))
def test_no_inline_grey_text(template):
    html = next(TEMPLATES.rglob(template)).read_text()
    assert not re.search(r"color:\s*(grey|gray|#808080|#999)", html), template
