"""Text a phone or an app controls is never rendered as markup.

A stalkerware app writes its own name (iOS CFBundleDisplayName), its
permission reasons and its entitlements; whoever manages a phone names its
configuration profiles and organisation; a rooted phone reports any model
name it likes. The content security policy stops injected scripts, but it
allows inline styles, so an app named `<style>tr{display:none}</style>`
could hide the red rows of a scan from the clinician. And the clinician's
browser holds every client's records.

This scans a phone whose every reported string carries markup, then reads
every page that shows the scan, and checks the markup arrives as text.
"""

import re
import time

import pytest

import isdi.scanner as scanner

MARK = "pwn"
# One payload per context: element content, a double-quoted attribute, a
# single-quoted attribute, and a style element.
PAYLOADS = [
    f'<style id="{MARK}0">tr{{display:none}}</style>',
    f'"><img src=x id="{MARK}1">',
    f"'><b id='{MARK}2'>",
    f'<a href="javascript:alert(1)" id="{MARK}3">x</a>',
]
HOSTILE = "".join(PAYLOADS)
# What would only be in the page if a payload were rendered as markup.
RAW = re.compile(r"<(style|img|b|a)\b[^>]*\bid=[\"']?" + MARK)

APPS = ["com.example.hidden", "com.whatsapp", "a.tck.lvmchi"]


IOS_SERIAL = "00008101-000A1C3E0E78001E"


@pytest.fixture(params=["android", "ios"])
def hostile_phone(request, monkeypatch):
    """A phone of each kind; yields (form device, serial). iPhone app names
    and management details come from the phone; Android names from the
    catalog."""
    if request.param == "ios":
        T, device, serial = scanner.IosScanner, "ios", IOS_SERIAL
        monkeypatch.setattr(T, "devices", lambda self: [IOS_SERIAL])
        monkeypatch.setattr(T, "get_system_apps", lambda self, s: [])
        monkeypatch.setattr(T, "get_offstore_apps", lambda self, s: [])
    else:
        T, device, serial = scanner.TestScanner, "test", "testdevice1"
    monkeypatch.setattr(T, "get_apps", lambda self, s: list(APPS))
    monkeypatch.setattr(
        T, "get_app_titles", lambda self, s: {a: f"Title {HOSTILE}" for a in APPS}
    )
    monkeypatch.setattr(
        T,
        "device_info",
        lambda self, serial: (
            f"Model {HOSTILE}",
            {"model": f"Model {HOSTILE}", "version": HOSTILE, "brand": HOSTILE},
        ),
    )
    monkeypatch.setattr(T, "isrooted", lambda self, s: (True, [f"Reason {HOSTILE}"]))
    monkeypatch.setattr(
        T,
        "device_management",
        lambda self, s: {
            "checked": True,
            "supervised": True,
            "organization": f"Org {HOSTILE}",
            "profiles": [{"name": f"Profile {HOSTILE}", "organization": HOSTILE}],
        },
    )
    monkeypatch.setattr(
        T,
        "dump_details",
        lambda self, appids: {
            a: {
                "title": f"Title {HOSTILE}",
                "permissions": [(f"Perm {HOSTILE}", f"Reason {HOSTILE}")],
                "versionName": HOSTILE,
                "data_usage": {
                    "data_used": HOSTILE,
                    "background_data_allowed": HOSTILE,
                },
                "battery_usage": HOSTILE,
            }
            for a in appids
        },
    )
    return device, serial


def _wait(client, job_id):
    for _ in range(200):
        state = client.get(f"/scan/status/{job_id}").json
        if state["status"] in ("done", "error"):
            return state
        time.sleep(0.05)
    raise AssertionError("scan did not finish")


def _check(page, where):
    match = RAW.search(page)
    assert not match, f"{where}: phone text rendered as markup: {match.group(0)}"


def test_hostile_phone_text_stays_text(client_of, no_csrf, hostile_phone):
    device, serial = hostile_phone
    client = client_of(f"20261101_hostile_{device}")
    client.get("/")
    r = client.post(
        "/scan/start",
        data={"device": device, "device_owner": f"Owner {HOSTILE}", "devid": serial},
    )
    job_id = r.json["job_id"]
    state = _wait(client, job_id)
    assert state["status"] == "done", state
    _check(str(state), "scan status")

    pages = {}
    result = client.get(f"/scan/result/{job_id}").get_data(as_text=True)
    pages["scan result"] = result
    scanid = re.search(r"/scan/(\d+)/", result).group(1)
    pages["saved scan"] = client.get(f"/scan/saved/{scanid}").get_data(as_text=True)
    rows = sorted(set(re.findall(rf"/scan/{scanid}/app/(\d+)", pages["saved scan"])))
    assert rows, "the saved scan links to no app pages"
    for row in rows:
        pages[f"app {row}"] = client.get(f"/scan/{scanid}/app/{row}").get_data(
            as_text=True
        )
    for lang in ("en", "es"):
        pages[f"client summary {lang}"] = client.get(
            f"/scan/{scanid}/client-summary?lang={lang}"
        ).get_data(as_text=True)
    pages["start page"] = client.get("/").get_data(as_text=True)

    # The consultation record, with this phone added to it.
    r = client.post("/consultation/devices/add", data={"scanid": scanid})
    assert r.status_code == 302, r.status_code
    pages["consultation"] = client.get("/consultation").get_data(as_text=True)
    device_pages = sorted(
        set(
            re.findall(
                r'href="(/consultation/devices/[^"/]+/(?:apps|questions))"',
                pages["consultation"],
            )
        )
    )
    assert len(device_pages) == 2, device_pages  # the apps and the questions
    for path in device_pages:
        pages[path] = client.get(path).get_data(as_text=True)
    for query in ("", "?copy=takehome", "?copy=takehome&lang=es"):
        pages[f"report{query}"] = client.get(f"/consultation/report{query}").get_data(
            as_text=True
        )

    for where, page in pages.items():
        _check(page, where)
    shown = "".join(pages.values())
    # The hostile text did reach the pages, as text.
    assert shown.count(f"id=&#34;{MARK}0") + shown.count(f"id=&quot;{MARK}0") > 0
    fields = ["Model", "Reason", "Owner"]
    if device == "ios":
        fields += ["Title", "Org", "Profile"]
    for field in fields:
        assert f"{field} &lt;style" in shown, f"{field} never shown"


def test_flag_text_is_escaped():
    """Flags come from ISDi's own lists, one of them synced weekly from a
    third party; an unknown flag is shown as its own text."""
    from isdi.scanner import blocklist

    html = blocklist.flag_str([f"x{PAYLOADS[0]}", f"y{PAYLOADS[1]}"])
    _check(html, "flag_str")
    assert "&lt;style" in html


def test_store_text_sanitizer_holds_up_to_random_markup():
    """Store descriptions are written by the app's developer and shown on
    the app page through clean_html. Whatever goes in, only bare allowed
    tags come out."""
    import random

    from isdi.htmlclean import ALLOWED, clean_description

    pieces = [
        "<",
        ">",
        "</",
        "/>",
        "<!--",
        "-->",
        "<![CDATA[",
        "]]>",
        "<!DOCTYPE x>",
        "<?x?>",
        "script",
        "style",
        "img",
        "a",
        "b",
        "p",
        "li",
        "iframe",
        "svg",
        "math",
        "textarea",
        " onerror=x",
        ' href="javascript:x"',
        " src=x",
        "'",
        '"',
        "=",
        "&",
        "&lt;",
        "&#60;",
        "text",
        " ",
        "\n",
        "\x00",
        "<b",
        "<p ",
        "<script>",
        "</script>",
        "<style>",
        "</style>",
    ]
    tag = re.compile(r"<(/?)([^>]*)>")
    rng = random.Random(20261101)
    for _ in range(3000):
        text = "".join(rng.choice(pieces) for _ in range(rng.randint(1, 25)))
        out = clean_description(text)
        rest = tag.sub("", out)
        assert "<" not in rest and ">" not in rest, (text, out)
        for closing, inner in tag.findall(out):
            assert inner in ALLOWED, (text, out)


def test_a_crash_carrying_phone_text_is_shown_as_text(client, no_csrf, monkeypatch):
    """The scan page shows errors as HTML (report_failure uses .html(), so
    fixed messages can carry a link). A crash's text can come from the
    phone, so it is escaped first."""

    def boom(self, s):
        raise RuntimeError(f"adb said {HOSTILE}")

    monkeypatch.setattr(scanner.TestScanner, "get_apps", boom)
    r = client.post(
        "/scan/start", data={"device": "test", "device_owner": "x", "devid": "t1"}
    )
    state = _wait(client, r.json["job_id"])
    assert state["status"] == "error"
    _check(state["error"], "crash message")
    assert "&lt;style" in state["error"]
