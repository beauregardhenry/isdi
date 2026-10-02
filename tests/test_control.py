"""Server control routes: deleting a device's data and Termux USB access."""

import json
import os
import subprocess

import pytest

from isdi.config import get_config
from isdi.scanner import db

SERIAL = "c" * 64  # stored serials are HMAC-SHA256 hex digests


@pytest.fixture
def stored_device(app):
    """A device with one scan, one app row and dump files on disk."""
    with app.app_context():
        scanid = db.create_scan(
            {
                "clientid": "control_test",
                "serial": SERIAL,
                "device": "android",
                "device_model": "Pixel",
                "device_version": "14",
                "device_primary_user": "owner",
                "device_manufacturer": "Google",
                "last_full_charge": "",
                "is_rooted": False,
                "rooted_reasons": "[]",
            }
        )
        db.create_mult_appinfo([(scanid, "org.example.a", "", "", "[]")])
    dump_dir = get_config().DUMP_DIR
    dumps = [os.path.join(dump_dir, f"{SERIAL}_android.{e}") for e in ("txt", "json")]
    other = os.path.join(dump_dir, f"{'d' * 64}_android.txt")
    for f in dumps + [other]:
        with open(f, "w") as fh:
            fh.write("dump")
    yield scanid, dumps, other
    for f in dumps + [other]:
        if os.path.exists(f):
            os.remove(f)


def test_delete_device_removes_its_scans_and_dumps(app, client, no_csrf, stored_device):
    scanid, dumps, other = stored_device
    r = client.post("/delete_device", data={"serial": SERIAL})
    assert r.status_code == 302
    with app.app_context():
        assert db.get_most_recent_scan_id(SERIAL) is None
        assert not db.query_db("select * from app_info where scanid=?", (scanid,))
    assert not any(os.path.exists(f) for f in dumps)
    assert os.path.exists(other), "another device's dump was deleted"


@pytest.mark.parametrize("serial", ["", "*", "../x", "c" * 63, SERIAL.upper()])
def test_delete_device_rejects_anything_but_a_stored_serial(
    client, no_csrf, stored_device, serial
):
    _, dumps, other = stored_device
    assert client.post("/delete_device", data={"serial": serial}).status_code == 400
    assert all(os.path.exists(f) for f in dumps + [other])


class FakeTermuxUsb:
    def __init__(self, listing="", returncode=0, error=None):
        self.listing, self.returncode, self.error = listing, returncode, error
        self.started = []

    def run(self, cmd, **kw):
        if self.error:
            raise self.error
        return subprocess.CompletedProcess(cmd, self.returncode, self.listing, "err")

    def popen(self, cmd, **kw):
        self.started.append(cmd)


@pytest.fixture
def termux(monkeypatch):
    from isdi.web.view import control

    def install(**kw):
        fake = FakeTermuxUsb(**kw)
        monkeypatch.setenv("PREFIX", "/data/data/com.termux/files/usr")
        monkeypatch.setattr(control.subprocess, "run", fake.run)
        monkeypatch.setattr(control.subprocess, "Popen", fake.popen)
        return fake

    return install


def test_termux_usb_is_refused_off_termux(client, no_csrf, monkeypatch):
    monkeypatch.delenv("PREFIX", raising=False)
    assert client.post("/termux-usb-permission").status_code == 403


def test_termux_usb_requests_permission_for_first_device(client, no_csrf, termux):
    fake = termux(listing=json.dumps(["/dev/bus/usb/001/002"]))
    r = client.post("/termux-usb-permission")
    assert r.status_code == 200 and r.json["device"] == "/dev/bus/usb/001/002"
    assert fake.started == [
        ["termux-usb", "-r", "-E", "-e", "usbmuxd -f -v", "/dev/bus/usb/001/002"]
    ]


@pytest.mark.parametrize(
    "kw, status",
    [
        ({"listing": "[]"}, 404),
        ({"listing": "not json"}, 500),
        ({"returncode": 1}, 500),
        ({"error": FileNotFoundError()}, 500),
        ({"error": subprocess.TimeoutExpired("termux-usb", 5)}, 500),
    ],
)
def test_termux_usb_failures_are_reported(client, no_csrf, termux, kw, status):
    fake = termux(**kw)
    r = client.post("/termux-usb-permission")
    assert r.status_code == status and "error" in r.json
    assert fake.started == []
