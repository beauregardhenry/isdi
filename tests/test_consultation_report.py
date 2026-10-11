"""The consultation report and the take-home copy."""

import io

import pytest

from isdi.consultation import report, screenshots, store
from isdi.scanner import db

CLIENT = "20260101_001"

pdf_ok = pytest.mark.skipif(
    not report.can_make_pdf(), reason="WeasyPrint is not installed"
)


@pytest.fixture(autouse=True)
def record(app):
    with app.app_context():
        db.get_db().execute("DELETE FROM screenshots")
        db.get_db().commit()
        store.save(CLIENT, "report_name", "Jane Client")
        store.save(
            CLIENT,
            "notes",
            {"client_notes": "CLIENT-SAID", "consultant_notes": "CONSULTANT-ONLY"},
        )
        store.save(
            CLIENT,
            "taq",
            {
                "sharing": {"share_phone_plan": "yes", "phone_plan_admin": ["poc"]},
                "legal": {"legal": ["ro"]},
            },
        )
        store.save(
            CLIENT,
            "accounts",
            [
                {
                    "account_id": 0,
                    "platform": "Mail",
                    "username": "jane@example.org",
                    "password_check": {"know": "yes"},
                }
            ],
        )
        store.save(
            CLIENT,
            "devices",
            [
                {
                    "key": "manual-1",
                    "manual": True,
                    "device_nickname": "old phone",
                    "is_rooted": "no",
                    "selected_apps": [
                        {
                            "title": "Hidden Tracker",
                            "flags": ["spyware"],
                            "install_info": {"knew_installed": "no"},
                            "notes": {"consultant_notes": "APP-CONSULTANT-NOTE"},
                        }
                    ],
                }
            ],
        )
        screenshots.save(
            CLIENT,
            "account:0:recovery_settings",
            screenshots.PNG + b"\0" * 32,
            "upload",
        )
    yield
    with app.app_context():
        for kind in store.KINDS:
            store.delete(CLIENT, kind)


def test_the_full_report_has_everything(client):
    page = client.get("/consultation/report").get_data(as_text=True)
    for text in (
        "Jane Client",
        CLIENT,
        "CLIENT-SAID",
        "CONSULTANT-ONLY",
        "APP-CONSULTANT-NOTE",
        "Shared phone plan",  # questionnaire risk
        "Password compromise",  # account risk
        "Risk from app: Hidden Tracker",
        "Person of concern",  # answer codes are shown as words
        "Restraining order",
        "Do you share a phone plan with the person of concern?",
        "SHA-256",
        "data:image/png;base64,",
    ):
        assert text in page, text


def test_the_take_home_copy_leaves_out_what_names_the_client_and_clinic(client):
    page = client.get("/consultation/report?copy=takehome").get_data(as_text=True)
    for text in (
        "Jane Client",
        CLIENT,
        "CONSULTANT-ONLY",
        "APP-CONSULTANT-NOTE",
        "ISDi",
        "SHA-256",
    ):
        assert text not in page, text
    assert "<title>Notes</title>" in page
    assert "CLIENT-SAID" in page and "Risk from app: Hidden Tracker" in page


def test_unanswered_questions_say_so(client):
    assert "Not answered" in client.get("/consultation/report").get_data(as_text=True)


def test_answers_are_escaped(app, client):
    with app.app_context():
        store.save(CLIENT, "notes", {"client_notes": "<script>alert(1)</script>"})
    page = client.get("/consultation/report").get_data(as_text=True)
    assert "<script>alert(1)</script>" not in page


def test_an_unknown_copy_is_refused(client):
    assert client.get("/consultation/report?copy=other").status_code == 400


def test_viewing_is_audited(app, client):
    from isdi import audit

    client.get("/consultation/report?copy=takehome")
    with app.app_context():
        entry = [e for e in audit.entries(CLIENT) if e["action"] == "report_viewed"][-1]
    assert entry["details"] == {"copy": "takehome"}


def test_the_name_is_saved(app, client, no_csrf):
    client.post("/consultation/report/name", data={"report_name": "  J. C.  "})
    with app.app_context():
        assert store.load(CLIENT, "report_name") == "J. C."


def test_another_client_s_record_is_not_in_the_report(client_of):
    page = client_of("20260101_444").get("/consultation/report").get_data(as_text=True)
    assert "Jane Client" not in page and "Hidden Tracker" not in page


@pdf_ok
def test_the_full_report_as_pdf(client, no_csrf):
    import pypdf

    r = client.post("/consultation/report.pdf", data={"copy": "full"})
    assert r.headers["Content-Type"] == "application/pdf"
    assert f"consultation-{CLIENT}.pdf" in r.headers["Content-Disposition"]
    text = "".join(p.extract_text() for p in pypdf.PdfReader(io.BytesIO(r.data)).pages)
    assert "Jane Client" in text and "Hidden Tracker" in text


@pdf_ok
def test_the_take_home_pdf_is_neutral_and_can_have_a_password(client, no_csrf):
    import pypdf

    r = client.post(
        "/consultation/report.pdf", data={"copy": "takehome", "password": "open sesame"}
    )
    assert (
        "notes-" in r.headers["Content-Disposition"]
        and CLIENT not in r.headers["Content-Disposition"]
    )
    reader = pypdf.PdfReader(io.BytesIO(r.data))
    assert reader.is_encrypted
    reader.decrypt("open sesame")
    assert reader.metadata.title == "Notes"
    assert "WeasyPrint" not in str(reader.metadata)
    text = "".join(p.extract_text() for p in reader.pages)
    assert "Jane Client" not in text and "Hidden Tracker" in text


@pdf_ok
def test_the_pdf_loads_nothing_from_outside(tmp_path, monkeypatch):
    seen = []
    real = report._refuse_fetch

    def record(url, *a, **k):
        seen.append(url)
        real(url)

    monkeypatch.setattr(report, "_refuse_fetch", record)
    secret = tmp_path / "secret.png"
    secret.write_bytes(screenshots.PNG)
    html = f'<img src="https://example.org/x.png"><img src="file://{secret}">'
    data = report.pdf(html, takehome=False)
    assert data.startswith(b"%PDF")
    assert sorted(seen) == sorted(["https://example.org/x.png", f"file://{secret}"])


def test_without_weasyprint_the_page_says_how_to_get_pdfs(client, monkeypatch):
    monkeypatch.setattr(report, "can_make_pdf", lambda: False)
    page = client.get("/consultation").get_data(as_text=True)
    assert "isdi-scanner[report]" in page and "Download it as PDF" not in page
