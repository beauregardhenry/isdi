"""Logs must not undo the pseudonymisation of device serials, or record
device output, app lists or email addresses."""

import logging
import subprocess

import pytest

import isdi.scanner as scanner
from isdi.config import get_config
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
    p = run_command("printf 'sec%sret' X; : {s}", s=f"-s {SERIAL}")
    assert p.stdout.read() == b"secXret"
    run_command("sh -c 'exit 3' -s {s}", s=SERIAL)
    assert SERIAL not in log_lines.text
    assert "secXret" not in log_lines.text


def test_android_dump_logs_a_pseudonym(log_lines, monkeypatch, tmp_path):
    def fake_run(argv, **kw):
        return subprocess.CompletedProcess(argv, 0, stdout="x=1\n" * 400, stderr="")

    monkeypatch.setattr(scanner.subprocess, "run", fake_run)
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
