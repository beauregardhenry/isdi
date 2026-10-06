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
