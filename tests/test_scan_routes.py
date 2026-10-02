"""Scan routes: input checks and failure reporting."""

import time

import pytest

import isdi.scanner as scanner
from isdi.web.view import scan as scan_view


@pytest.mark.parametrize(
    "form, status, message",
    [
        ({"device_owner": "x"}, 400, "choose one device"),
        ({"device": "test"}, 400, "nickname"),
        ({"device": "windows", "device_owner": "x"}, 400, "choose one device"),
        (
            {"device": "test", "device_owner": "x", "devid": "a;rm -rf /"},
            400,
            "Invalid device id",
        ),
    ],
)
def test_scan_start_rejects_bad_input(client, no_csrf, form, status, message):
    r = client.post("/scan/start", data=form)
    assert r.status_code == status and message in r.json["error"]


def test_scan_start_needs_a_session(app, no_csrf):
    r = app.test_client().post("/scan/start", data={"device": "test"})
    assert r.status_code == 401


def test_scan_start_without_a_connected_device(client, no_csrf, monkeypatch):
    monkeypatch.setattr(scanner.TestScanner, "devices", lambda self: [])
    r = client.post("/scan/start", data={"device": "test", "device_owner": "x"})
    assert r.status_code == 409 and "wasn't detected" in r.json["error"]


def _wait_for(client, job_id):
    for _ in range(100):
        r = client.get(f"/scan/status/{job_id}")
        if r.json["status"] in ("done", "error"):
            return r.json
        time.sleep(0.05)
    raise AssertionError("scan job did not finish")


def test_failed_scan_is_reported(client, no_csrf, monkeypatch):
    monkeypatch.setattr(scanner.TestScanner, "get_apps", lambda self, s: [])
    r = client.post(
        "/scan/start", data={"device": "test", "device_owner": "x", "devid": "t1"}
    )
    job = _wait_for(client, r.json["job_id"])
    assert job["status"] == "error" and "scanning failed" in job["error"]
    r = client.get(f"/scan/result/{r.json['job_id']}")
    assert r.status_code == 202


def test_crashing_scan_is_reported(client, no_csrf, monkeypatch):
    def boom(self, s):
        raise RuntimeError("adb went away")

    monkeypatch.setattr(scanner.TestScanner, "get_apps", boom)
    r = client.post(
        "/scan/start", data={"device": "test", "device_owner": "x", "devid": "t1"}
    )
    job = _wait_for(client, r.json["job_id"])
    assert job["status"] == "error" and "adb went away" in job["error"]


def test_unknown_scan_job(client):
    assert client.get("/scan/status/nope").status_code == 404


@pytest.mark.parametrize(
    "query, message",
    [
        ({"device_owner": "x"}, b"Please choose one device"),
        ({"device": "test"}, b"Please give the device a nickname"),
        ({"device": "test", "device_owner": "x", "devid": "a;b"}, b"Invalid device id"),
        (
            {"device": "test", "device_owner": "x", "devid": "a;b", "from_dump": "1"},
            b"Invalid device id",
        ),
        (
            {
                "device": "test",
                "device_owner": "x",
                "devid": "f" * 64,
                "from_dump": "1",
            },
            b"No scan found for this device",
        ),
    ],
)
def test_scan_page_reports_bad_input(client, query, message):
    r = client.get("/scan", query_string=query)
    assert r.status_code == 201 and message in r.data


@pytest.mark.parametrize(
    "rooted, reasons, expected",
    [
        (
            True,
            ["su found", "magisk"],
            "Detected</strong>. Reason(s): su found; magisk",
        ),
        (None, [], "Not Detected (some checks incomplete)"),
        (False, [], "Not Detected"),
        (True, ["<b>x</b>"], "&lt;b&gt;x&lt;/b&gt;"),
    ],
)
def test_root_status_text(rooted, reasons, expected):
    assert expected in scan_view._isrooted_html(rooted, reasons)
