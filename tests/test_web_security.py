import os
import shlex
import stat
from pathlib import Path

import pytest

from isdi.config import get_config
from isdi.scanner import root_check
from isdi.scanner.runcmd import (
    is_valid_appid,
    is_valid_hmac_serial,
    is_valid_serial,
)

INJECTION = "x; touch /tmp/isdi-pwned #"


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


def _csp_nonce(resp):
    import re

    m = re.search(r"'nonce-([^']+)'", resp.headers["Content-Security-Policy"])
    assert m, resp.headers["Content-Security-Policy"]
    return m.group(1)


def test_csp_blocks_inline_script(client):
    csp = client.get("/instruction").headers["Content-Security-Policy"]
    script_src = next(d for d in csp.split(";") if d.strip().startswith("script-src"))
    assert "'unsafe-inline'" not in script_src
    assert "'unsafe-eval'" not in script_src
    for directive in ("object-src 'none'", "base-uri 'none'", "frame-ancestors 'none'"):
        assert directive in csp


def test_csp_nonce_is_fresh_per_response(client):
    assert _csp_nonce(client.get("/instruction")) != _csp_nonce(
        client.get("/instruction")
    )


@pytest.mark.parametrize("url", ["/", "/instruction", "/privacy", "/form/"])
def test_pages_only_use_nonced_scripts(client, url):
    """Every inline <script> must carry this response's nonce, and no
    inline on* handlers may remain (CSP would silently drop them)."""
    import re

    r = client.get(url)
    assert r.status_code == 200
    html = r.get_data(as_text=True)
    # Commented-out markup is never parsed, so ignore it.
    html = re.sub(r"<!--.*?-->", "", html, flags=re.S)
    nonce = _csp_nonce(r)
    for tag in re.findall(r"<script\b[^>]*>", html):
        assert "src=" in tag or f'nonce="{nonce}"' in tag, tag
    assert not re.search(r"\son[a-z]+\s*=", html, re.I)
    assert "javascript:" not in html


def test_every_app_gets_all_routes(app):
    """Routes live on a blueprint, so a second create_app() in the same
    process (tests, the CLI, a WSGI server) is not left without pages."""
    from isdi.app import create_app

    other = create_app(get_config("test"))
    rules = lambda a: {r.rule for r in a.url_map.iter_rules()}
    assert rules(other) == rules(app)
    assert {"/", "/scan", "/form/", "/kill"} <= rules(other)


def test_templates_only_reference_static_files_that_exist(app):
    """A missing file fails silently in the browser (a 404 image or script)."""
    import re

    templates = Path(app.template_folder)
    static = Path(app.static_folder)
    pattern = re.compile(r"url_for\(['\"]static['\"],\s*filename=['\"]([^'\"]+)")
    refs = {
        (t.name, m)
        for t in templates.glob("*.html")
        for m in pattern.findall(t.read_text(encoding="utf-8"))
    }
    assert refs, "pattern no longer matches the templates"
    missing = [(t, f) for t, f in refs if not (static / f).is_file()]
    assert not missing
