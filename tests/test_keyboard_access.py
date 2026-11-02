"""What a keyboard or touch-screen user can read.

A keyboard-only walk of every page (Playwright, 2026-11-01) found every
control reachable with a visible focus ring. It also found explanations
kept only in hover tooltips, which a keyboard or a touch screen cannot
open:
- what each flag means ("Ask whether the client installed it."), only in
  an <abbr title>;
- what "Managed (supervision, profiles)" means, a tooltip on a label;
- the uninstall buttons, named only by the symbol they show.
"""

import re
import time

import pytest

from isdi.scanner import blocklist


def _scan(client):
    r = client.post(
        "/scan/start", data={"device": "test", "device_owner": "x", "devid": "t1"}
    )
    job = r.json["job_id"]
    for _ in range(200):
        if client.get(f"/scan/status/{job}").json["status"] in ("done", "error"):
            break
        time.sleep(0.05)
    page = client.get(f"/scan/result/{job}").get_data(as_text=True)
    return int(re.search(r"/scan/(\d+)/", page).group(1)), page


def _legend(page):
    m = re.search(
        r"<details[^>]*>\s*<summary>What the flags mean</summary>(.*?)</details>",
        page,
        re.S,
    )
    assert m, "no flag legend"
    return m.group(1)


def test_flag_descriptions_are_public():
    text = blocklist.flag_description("hidden-with-powers")
    assert "Ask whether the client installed it." in text
    assert blocklist.flag_description("not-a-flag") == "not-a-flag"


def test_scan_results_explain_their_flags_in_text(client_of, no_csrf):
    client = client_of("20261101_kb1")
    client.get("/")
    scanid, live = _scan(client)
    saved = client.get(f"/scan/saved/{scanid}").get_data(as_text=True)
    for page in (live, saved):
        legend = _legend(page)
        # The demo phone has a listed stalkerware app and a dual-use app.
        assert blocklist.flag_description("stalkerware") in legend
        assert blocklist.flag_description("dual-use") in legend
        # Only flags this scan has.
        assert blocklist.flag_description("hidden-with-powers") not in legend


def test_device_apps_page_explains_its_flags(client_of, no_csrf):
    client = client_of("20261101_kb2")
    client.get("/")
    scanid, _ = _scan(client)
    r = client.post("/consultation/devices/add", data={"scanid": scanid})
    page = client.get(r.headers["Location"]).get_data(as_text=True)
    assert blocklist.flag_description("stalkerware") in _legend(page)


def test_managed_explanation_is_visible_text():
    from pathlib import Path

    tpl = (
        Path(__file__).resolve().parent.parent / "src/isdi/web/templates/home.html"
    ).read_text()
    explanation = "can be controlled and monitored by whoever manages it"
    assert explanation in tpl
    # Not only inside a title="..." attribute.
    assert re.search(r">[^<]*" + explanation, tpl), "explanation only in a tooltip"


def test_uninstall_buttons_are_named(client_of, no_csrf):
    client = client_of("20261101_kb3")
    client.get("/")
    _, page = _scan(client)
    buttons = re.findall(r'<a [^>]*data-action="delete-app"[^>]*>', page)
    assert buttons
    for b in buttons:
        assert re.search(r'aria-label="Uninstall [^"]+"', b), b
    system = re.findall(r"<a [^>]*>&otimes;</a>", page)
    for s in system:
        assert "aria-label" in s, s
