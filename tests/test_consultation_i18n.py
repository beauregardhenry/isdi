"""The take-home copy in Spanish, with the client summary's safety guidance.

Two checks keep the translation complete: every question, answer choice and
risk text in the code has a Spanish entry, and the take-home copy renders in
Spanish in strict mode (untranslated text raises) for a full and an empty
record."""

import re
from pathlib import Path

import pytest
from flask import render_template

from isdi import client_summary
from isdi.consultation import i18n, model, report, store
from isdi.consultation.choices import answer_text

CLIENT = "20260101_001"
SRC = Path(__file__).resolve().parent.parent / "src" / "isdi"


def _all_questions():
    out = []

    def walk(node):
        for value in node.values():
            if isinstance(value, dict):
                walk(value)
            else:
                out.append(value)

    walk(model.Consultation.questions())
    return out


def _risk_texts():
    """Every literal risk name and description in the model, read from the
    source, so a risk added later without a translation fails here."""
    text = (SRC / "consultation" / "model.py").read_text()
    found = re.findall(r'(?:risk|description)="((?:[^"\\]|\\.)*)"', text)
    found += re.findall(
        r'description = "((?:[^"\\]|\\.)*)"', text
    )  # InstallInfo builds its description first
    found = [s for s in found if s and "{}" not in s]
    # Sentences appended to a description ("description += ...") must be
    # covered by an entry that ends with them.
    for extra in re.findall(r'description \+= "((?:[^"\\]|\\.)*)"', text):
        assert any(k.endswith(extra) for k in i18n.ES), extra
    return found


def _template_titles():
    html = (SRC / "web" / "templates" / "consultation" / "report.html").read_text()
    titles = []
    for block in re.findall(r"\{% set \w+_titles = (\{.*?\}) %\}", html):
        titles += re.findall(r':\s*"([^"]+)"', block)
    return titles


@pytest.mark.parametrize(
    "source",
    ["questions", "choices", "risks", "titles"],
)
def test_everything_in_the_code_has_a_spanish_entry(source):
    texts = {
        "questions": _all_questions,
        "choices": lambda: list(answer_text().values()),
        "risks": _risk_texts,
        "titles": _template_titles,
    }[source]()
    assert texts, source
    missing = [s for s in texts if s not in i18n.ES]
    assert missing == []


def test_risks_built_around_a_name():
    t = i18n.translator("es", strict=True)
    assert (
        t("Risk from app: Hidden Tracker") == "Riesgo de la aplicación: Hidden Tracker"
    )
    assert t("Risks identified: Spyware application, Data leakage.") == (
        "Riesgos encontrados: Aplicación espía, Filtración de datos."
    )


def test_english_and_free_text_pass_through():
    t = i18n.translator("en", strict=True)
    assert t("Notes") == "Notes"
    es = i18n.translator("es")  # not strict: what staff typed stays as typed
    assert es("my own words") == "my own words" and es(None) is None
    with pytest.raises(KeyError):
        i18n.translator("es", strict=True)("my own words")


FULL = {
    "taq": {
        "marked_done": True,
        "devices": {
            "live_together": "yes",
            "purchase_device": "yes",
            "purchase_device_which": "the phone",
            "physical_access": "yes",
            "physical_access_which": "the tablet",
            "device_pin": "yes",
        },
        "accounts": {
            "pwd_mgmt": ["paper", "pwd_manager"],
            "pwd_mgmt_describe": "a notebook",
            "pwd_comp": "yes",
            "pwd_comp_which": "email",
        },
        "sharing": {
            "share_phone_plan": "yes",
            "phone_plan_admin": ["poc"],
            "share_accounts": "yes",
            "share_which": "streaming",
        },
        "smarthome": {
            "smart_home": "yes",
            "smart_home_setup": ["poc"],
            "smart_home_access": "yes",
            "smart_home_acct_sharing": "yes",
            "smart_home_acct_linking": "yes",
        },
        "kids": {
            "custody": "yes",
            "child_phys_access": "yes",
            "child_phone_plan": "yes",
        },
        "legal": {"legal": ["ro", "div", "cl", "other_legal"]},
    },
    "accounts": [
        {
            "account_id": 0,
            "platform": "Mail",
            "username": "someone@example.org",
            "suspicious_logins": {
                "recognize": "yes",
                "describe_logins": "a laptop",
                "activity_log": "yes",
                "describe_activity": "at night",
            },
            "password_check": {
                "last_updated": "last year",
                "know": "yes",
                "guess": "yes",
                "federated": "yes",
                "federated_which": "Google",
                "federated_comp": "yes",
            },
            "recovery_settings": {
                "phone_present": "yes",
                "phone": "555",
                "phone_access": "yes",
                "email_present": "yes",
                "email": "x@example.org",
                "email_access": "yes",
            },
            "two_factor_settings": {
                "enabled": "yes",
                "second_factor_type": "authenticator_app",
                "describe": "an app",
                "second_factor_access": "yes",
            },
            "security_questions": {"present": "yes", "know": "yes", "which": "pet"},
            "notes": {"client_notes": "MY-WORDS"},
        },
        {
            "account_id": 1,
            "platform": "Chat",
            "username": "other",
            "two_factor_settings": {"enabled": "no"},
        },
    ],
    "devices": [
        {
            "key": "manual-1",
            "manual": True,
            "device_nickname": "",
            "device_type": "android",
            "is_rooted": "yes",
            "selected_apps": [
                {
                    "title": "Hidden Tracker",
                    "appId": "com.hidden.tracker",
                    "flags": ["spyware", "regex-spy"],
                    "install_time": "2026-01-01",
                    "app_version": "1.0",
                    "install_info": {"knew_installed": "no"},
                    "permission_info": {"access": "yes", "describe": "location"},
                    "notes": {"client_notes": "APP-WORDS"},
                },
                {
                    "title": "Other",
                    "flags": [],
                    "install_info": {"knew_installed": "yes", "installed": "no"},
                },
                {
                    "title": "Third",
                    "flags": [],
                    "install_info": {
                        "knew_installed": "yes",
                        "installed": "yes",
                        "coerced": "yes",
                    },
                },
            ],
        }
    ],
    "notes": {"client_notes": "CLIENT-SAID", "consultant_notes": "CONSULTANT-ONLY"},
}


@pytest.fixture
def filled(app):
    with app.app_context():
        for kind, doc in FULL.items():
            store.save(CLIENT, kind, doc)
    yield
    with app.app_context():
        for kind in store.KINDS:
            store.delete(CLIENT, kind)


@pytest.fixture
def empty(app):
    with app.app_context():
        for kind in store.KINDS:
            store.delete(CLIENT, kind)


def _strict_spanish(app):
    with app.test_request_context():
        ctx = report.context(CLIENT, takehome=True, lang="es", strict=True)
        return render_template("consultation/report.html", **ctx)


def test_a_full_record_renders_entirely_in_spanish(app, filled):
    html = _strict_spanish(app)  # raises on any untranslated text
    assert '<html lang="es">' in html and "<title>Notas</title>" in html
    for kept in ("CLIENT-SAID", "MY-WORDS", "APP-WORDS", "Hidden Tracker"):
        assert kept in html  # what was typed is not translated
    assert "CONSULTANT-ONLY" not in html


def test_an_empty_record_renders_entirely_in_spanish(app, empty):
    html = _strict_spanish(app)
    assert "No se registraron dispositivos." in html
    assert "No se revisaron cuentas." in html


def test_the_take_home_copy_carries_the_safety_guidance(client, filled):
    for lang in ("en", "es"):
        page = client.get(f"/consultation/report?copy=takehome&lang={lang}").get_data(
            as_text=True
        )
        text = client_summary.TEXT[lang]
        assert text["h_limits"] in page and text["h_next"] in page
        for item in text["limits"] + text["next"]:
            assert item in page
    english = client.get("/consultation/report?copy=takehome").get_data(as_text=True)
    assert "Antes de cambiar algo" not in english


def test_the_full_report_stays_english_and_without_guidance(client, filled):
    page = client.get("/consultation/report?lang=es").get_data(as_text=True)
    assert '<html lang="en">' in page and "Consultation report" in page
    assert client_summary.TEXT["en"]["h_next"] not in page


def test_the_language_is_audited(app, client, filled):
    from isdi import audit

    client.get("/consultation/report?copy=takehome&lang=es")
    with app.app_context():
        entry = [e for e in audit.entries(CLIENT) if e["action"] == "report_viewed"][-1]
    assert entry["details"] == {"copy": "takehome", "lang": "es"}


def test_the_consultation_page_offers_spanish(client, filled):
    page = client.get("/consultation").get_data(as_text=True)
    assert "copy=takehome&amp;lang=es" in page
    assert '<option value="es" lang="es">Español</option>' in page


@pytest.mark.skipif(not report.can_make_pdf(), reason="WeasyPrint is not installed")
def test_a_spanish_take_home_pdf(app, client, filled, no_csrf):
    from isdi import audit

    r = client.post("/consultation/report.pdf", data={"copy": "takehome", "lang": "es"})
    assert r.status_code == 200 and r.data.startswith(b"%PDF")
    with app.app_context():
        entry = [e for e in audit.entries(CLIENT) if e["action"] == "report_made"][-1]
    assert entry["details"] == {"copy": "takehome", "lang": "es", "password": False}
