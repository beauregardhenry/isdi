"""Logs must not undo the pseudonymisation of device serials, or record
device output, app lists or email addresses."""

import logging
import subprocess
from pathlib import Path

import pytest

import isdi.scanner as scanner
from isdi.config import get_config
from isdi.scanner import parse_dump
from isdi.scanner.runcmd import RedactingFilter, redact, run_command

SERIAL = "R58M12ABCDE"


@pytest.mark.parametrize(
    "text",
    [
        f"adb -s {SERIAL} shell getprop",
        f"adb -s '{SERIAL}' shell getprop",
        f"python -m pymobiledevice3 apps list --udid {SERIAL}",
        f"python -m pymobiledevice3 apps list --udid={SERIAL}",
        f'127.0.0.1 - - [02/Oct/2026 17:46:08] "GET /details/app/android?serial={SERIAL}&appId=com.x HTTP/1.1" 200 -',
        f"Account owner jane.doe@example.org on {SERIAL}".replace(f" on {SERIAL}", ""),
    ],
)
def test_redact_removes_serials_query_strings_and_emails(text):
    out = redact(text)
    assert SERIAL not in out and "jane.doe" not in out and "com.x" not in out


def test_redact_keeps_ordinary_messages():
    assert redact("Dumping android device device-0123abcd...") == (
        "Dumping android device device-0123abcd..."
    )
    assert redact('"GET /scan/status/abc HTTP/1.1" 200') == (
        '"GET /scan/status/abc HTTP/1.1" 200'
    )


@pytest.fixture
def log_lines(caplog):
    caplog.set_level(logging.DEBUG)
    caplog.handler.addFilter(RedactingFilter())
    return caplog


def test_commands_and_their_output_are_not_logged(log_lines):
    # printf prints "secXret": output that is not part of the command text.
    p = run_command(["sh", "-c", "printf 'sec%sret' X", "-s", SERIAL])
    assert p.stdout.read() == b"secXret"
    run_command(["sh", "-c", "exit 3", "-s", SERIAL])
    assert SERIAL not in log_lines.text
    assert "secXret" not in log_lines.text


def test_android_dump_logs_a_pseudonym(log_lines, monkeypatch, tmp_path):
    def fake_run(argv, **kw):
        return subprocess.CompletedProcess(argv, 0, stdout="x=1\n" * 400, stderr="")

    monkeypatch.setattr(scanner.android.subprocess, "run", fake_run)
    sc = scanner.AndroidScanner()
    monkeypatch.setattr(sc, "dump_path", lambda serial: str(tmp_path / "d.txt"))
    assert sc._dump_phone(SERIAL)
    assert SERIAL not in log_lines.text
    assert get_config().hmac_serial(SERIAL)[:12] in log_lines.text


def test_log_file_redacts_and_never_gets_debug_records(monkeypatch, tmp_path):
    cfg = get_config()
    monkeypatch.setattr(cfg, "logs_dir", tmp_path)
    root = logging.getLogger()
    before = list(root.handlers)
    monkeypatch.setattr(root, "handlers", [])
    try:
        # As at startup: a module-level logging call before setup_logger()
        # installs a default stderr handler (logging.basicConfig()).
        logging.error("usbmuxd not running")
        cfg.setup_logger()
        logging.getLogger("werkzeug").info(
            '"GET /privacy/android/account?serial=%s HTTP/1.1" 200 -', SERIAL
        )
        logging.debug("device output for %s", SERIAL)
        for h in root.handlers:
            h.flush()
        text = (tmp_path / "isdi.log").read_text()
    finally:
        for h in root.handlers:
            h.close()
        root.handlers[:] = before
    assert "GET /privacy/android/account?<redacted>" in text
    assert SERIAL not in text
    assert "device output" not in text
    assert (tmp_path / "isdi.log").stat().st_mode & 0o077 == 0


# --- app ids and device output in the scanner's own messages ---------------------

FIXTURES = Path(__file__).parent / "fixtures"
SECRET_APP = "com.secret.tracker"


def _not_in_log(text, *values):
    for v in values:
        assert v not in text, f"{v!r} was logged"


def test_android_missing_app_is_not_named(log_lines):
    dump = parse_dump.AndroidDump(str(FIXTURES / "android_dump.txt"))
    assert dump.info(SECRET_APP) == {}
    assert log_lines.records  # the miss is still reported
    _not_in_log(log_lines.text, SECRET_APP)


def test_android_bad_package_key_is_not_quoted(log_lines, tmp_path):
    text = (FIXTURES / "android_dump.txt").read_text()
    dumpf = tmp_path / "dump.txt"
    dumpf.write_text(
        text.replace(
            "  Package [com.whatsapp] (9a8b7c6):", "  Package com.secret.tracker:"
        )
    )
    parse_dump.AndroidDump(str(dumpf)).info("com.example.spy")
    _not_in_log(log_lines.text, SECRET_APP)


def test_ios_missing_app_is_not_named(log_lines, tmp_path):
    dumpf = tmp_path / "dump.json"
    dumpf.write_text((FIXTURES / "ios_dump.json").read_text())
    dump = parse_dump.IosDump(str(dumpf))
    assert not dump.info(SECRET_APP)
    _not_in_log(log_lines.text, SECRET_APP, str(dumpf))


def test_unreadable_ios_dump_is_not_named(log_lines, tmp_path):
    dumpf = tmp_path / f"{get_config().hmac_serial(SERIAL)}.json"
    dumpf.write_text('{"broken": ' + SECRET_APP)
    parse_dump.IosDump(str(dumpf))
    assert log_lines.records
    _not_in_log(log_lines.text, SECRET_APP, str(dumpf), dumpf.stem)


def test_title_lookup_error_does_not_name_the_app(log_lines, monkeypatch):
    class Broken:
        def cursor(self):
            raise RuntimeError(f"no such table while reading {SECRET_APP}")

    sc = scanner.AndroidScanner()
    monkeypatch.setattr(scanner.AppScanner, "app_info_conn", Broken())
    monkeypatch.setattr(sc, "get_apps", lambda s: [SECRET_APP])
    monkeypatch.setattr(sc, "get_offstore_apps", lambda s: [])
    monkeypatch.setattr(sc, "get_system_apps", lambda s: [])
    monkeypatch.setattr(sc, "dump_details", lambda appids: {})
    sc.find_spyapps(SERIAL)
    assert log_lines.records
    _not_in_log(log_lines.text, SECRET_APP)
