import os
import shlex
import stat

import pytest

from isdi.config import get_config
from isdi.scanner import root_check
from isdi.scanner.runcmd import (
    is_valid_appid,
    is_valid_hmac_serial,
    is_valid_serial,
)

INJECTION = "x; touch /tmp/isdi-pwned #"


@pytest.fixture(scope="module")
def app():
    from isdi.app import create_app

    app = create_app(get_config("test"))
    app.config["TESTING"] = True
    return app


@pytest.fixture
def client(app):
    c = app.test_client()
    with c.session_transaction() as s:
        s["clientid"] = "20260101_001"
    return c


@pytest.fixture
def no_subprocess(monkeypatch):
    """Fail the test if anything tries to spawn a process."""
    import subprocess

    calls = []

    def _popen(*args, **kwargs):
        calls.append(args)
        raise AssertionError(f"unexpected subprocess: {args!r}")

    monkeypatch.setattr(subprocess, "Popen", _popen)
    monkeypatch.setattr(subprocess, "run", _popen)
    return calls


@pytest.mark.parametrize(
    "serial", ["R58M12ABCDE", "emulator-5554", "192.168.1.5:5555", "00008030-001A"]
)
def test_valid_serials(serial):
    assert is_valid_serial(serial)


@pytest.mark.parametrize(
    "serial", ["", None, INJECTION, "-s", "a b", "a'b", "$(id)", "a`id`", "x\n"]
)
def test_invalid_serials(serial):
    assert not is_valid_serial(serial)


def test_appid_validation():
    assert is_valid_appid("com.example.app_1")
    assert is_valid_appid("com.example-app")
    for bad in ["", None, "--user", "a;b", "a b", "a'b"]:
        assert not is_valid_appid(bad)


def test_hmac_serial_validation():
    assert is_valid_hmac_serial(get_config().hmac_serial("abc"))
    for bad in ["*", "../../etc", "abc", "A" * 64]:
        assert not is_valid_hmac_serial(bad)


def test_privacy_rejects_injected_serial(client, no_subprocess):
    r = client.get("/privacy/android/account", query_string={"serial": INJECTION})
    assert r.status_code == 400
    assert not no_subprocess


def test_details_rejects_injected_params(client, no_subprocess):
    r = client.get(
        "/details/app/android", query_string={"appId": "a;id", "serial": "ok"}
    )
    assert r.status_code == 400
    r = client.get("/details/app/nope", query_string={"appId": "a", "serial": "b"})
    assert r.status_code == 400


def test_scan_start_rejects_injected_serial(app, client, no_subprocess):
    app.config["WTF_CSRF_ENABLED"] = False
    try:
        r = client.post(
            "/scan/start",
            data={"device": "android", "device_owner": "a", "devid": INJECTION},
        )
    finally:
        app.config["WTF_CSRF_ENABLED"] = True
    assert r.status_code == 400


def test_post_without_csrf_token_is_rejected(client):
    r = client.post("/delete_device", data={"serial": "0" * 64})
    assert r.status_code == 400
    assert b"CSRF" in r.data


def test_kill_requires_post(client):
    assert client.get("/kill").status_code == 405


def test_delete_app_requires_post(client):
    assert client.get("/delete/app/1").status_code == 405


def test_security_headers(client):
    r = client.get("/instruction")
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["Referrer-Policy"] == "no-referrer"


def test_default_host_is_loopback():
    assert get_config().host == "127.0.0.1"


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_secret_files_are_private():
    cfg = get_config()
    for path in (cfg.pii_key_file, cfg.flask_secret_file):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_root_check_quotes_device_command(monkeypatch):
    """The device-side command must reach adb as a single argument."""
    seen = []

    class _P:
        returncode = 0

    def fake_run_command(cmd, **kwargs):
        seen.append(cmd.format(**kwargs))
        return _P()

    monkeypatch.setattr(root_check, "run_command", fake_run_command)
    monkeypatch.setattr(root_check, "catch_err", lambda p, cmd="": "")
    root_check.check_android_root("SERIAL1", "adb")

    by_cmd = {c["cmd_str"]: c for c in root_check.ANDROID_ROOT_INDICATORS}
    assert len(seen) == len(by_cmd)
    for line in seen:
        argv = shlex.split(line)
        assert argv[:4] == ["adb", "-s", "SERIAL1", "shell"]
        assert len(argv) == 5 and argv[4] in by_cmd
