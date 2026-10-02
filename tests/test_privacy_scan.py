"""Privacy-check screenshots: shown inline, never written to disk."""

import base64
import subprocess

import pytest

from isdi.scanner import privacy_scan_android as ps

PNG = ps.PNG_SIGNATURE + b"fake image body"


@pytest.fixture
def adb(monkeypatch):
    """Fake subprocess.run for adb; set .stdout or .error before calling."""

    class Fake:
        argv = None
        stdout = PNG
        error = None

    def fake_run(argv, **kw):
        Fake.argv = argv
        if Fake.error:
            raise Fake.error
        return subprocess.CompletedProcess(argv, 0, stdout=Fake.stdout, stderr=b"")

    monkeypatch.setattr(ps, "run", fake_run)
    return Fake


def test_screenshot_is_returned_inline(adb, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    html = ps.take_screenshot("SER 1")
    assert html.startswith("<img") and "data:image/png;base64," in html
    encoded = html.split("base64,", 1)[1].split("'", 1)[0]
    assert base64.b64decode(encoded) == PNG
    assert list(tmp_path.iterdir()) == []


def test_serial_is_one_argument(adb):
    ps.take_screenshot("SER 1")
    assert adb.argv == [ps.adb, "-s", "SER 1", "exec-out", "screencap", "-p"]


def test_non_image_output_is_reported(adb):
    adb.stdout = b"error: device unauthorized"
    html = ps.take_screenshot("SER1")
    assert "screenshotfail" in html and "<img" not in html


def test_adb_failure_is_reported(adb):
    adb.error = subprocess.CalledProcessError(1, ["adb"])
    assert "exit code 1" in ps.take_screenshot("SER1")


def test_error_text_is_escaped(adb):
    adb.error = OSError("<script>alert(1)</script>")
    html = ps.take_screenshot("SER1")
    assert "<script>" not in html and "&lt;script&gt;" in html


def test_legacy_screenshot_file_is_removed(adb, tmp_path, monkeypatch):
    old = tmp_path / "tmp.png"
    old.write_bytes(PNG)
    monkeypatch.setattr(ps, "LEGACY_SCREENSHOT", old)
    assert "data:image/png" in ps.do_privacy_check("SER1", "screenshot")
    assert not old.exists()


def test_screenshot_route_returns_inline_image(adb, client):
    r = client.get("/privacy/android/screenshot", query_string={"serial": "SER1"})
    assert r.status_code == 200
    assert b"data:image/png;base64," in r.data
