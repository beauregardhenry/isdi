"""What AndroidScanner writes to a dump file: account emails redacted and
dumpsys lines normalized the way scripts/android_scan.sh's sed did."""

import subprocess

import pytest

import isdi.scanner as scanner
from isdi.scanner import parse_dump

PACKAGE_DUMPSYS = """\
Database versions:
  Internal:
    sdkVersion=34
Packages:
  Package [com.example.spy] (5d6e7f8):
    userId=10234
    versionName=2.1
    flags=[ HAS_CODE ]
    User 0: ceDataInode=12345 installed=true hidden=false
      firstInstallTime=2026-09-01 12:00:00
"""


@pytest.mark.parametrize(
    "text, expected",
    [
        (
            "  Account {name=jane.doe@gmail.com, type=com.google}",
            "  Account {name=<email>, type=com.google}",
        ),
        (
            "    /data/user/0/x/databases/jane.doe_gmail.com.db",
            "    /data/user/0/x/databases/<db_email>.db",
        ),
        ("nothing personal here", "nothing personal here"),
    ],
)
def test_redact_emails(text, expected):
    assert parse_dump.redact_emails(text) == expected


def test_user_0_block_is_split_onto_its_own_lines():
    out = parse_dump.normalize_dumpsys(
        "    User 0: ceDataInode=12345 installed=true\n      firstInstallTime=x\n"
    )
    assert (
        out
        == "    User 0:\n      ceDataInode=12345 installed=true\n      firstInstallTime=x\n"
    )


def test_comment_markers_and_excluded_packages():
    assert parse_dump.normalize_dumpsys("  # note\n") == "   note\n"
    assert (
        parse_dump.normalize_dumpsys("Excluded packages:\n") == "  Excluded packages:\n"
    )


def test_normalization_never_joins_lines():
    text = "a=1\n\n   \n#b\nc=3\n"
    assert parse_dump.normalize_dumpsys(text).count("\n") == text.count("\n")


@pytest.fixture
def fake_adb(monkeypatch):
    """Fake `adb -s SER shell ...`: package dumpsys returns PACKAGE_DUMPSYS
    plus an account email; everything else returns filler."""

    def fake_run(argv, **kw):
        args = argv[3:]
        if args[:2] == ["shell", "dumpsys"] and args[2:] == ["package"]:
            out = PACKAGE_DUMPSYS + "  owner=jane.doe@gmail.com\n"
        else:
            out = "x=1\n" * 400  # keep the dump above the 5000-byte sanity floor
        return subprocess.CompletedProcess(argv, 0, stdout=out, stderr="")

    monkeypatch.setattr(scanner.subprocess, "run", fake_run)


def test_dump_file_is_redacted_normalized_and_parses(fake_adb, tmp_path, monkeypatch):
    sc = scanner.AndroidScanner()
    dumpf = tmp_path / "SER_android.txt"
    monkeypatch.setattr(sc, "dump_path", lambda serial: str(dumpf))

    assert sc._dump_phone("SER1") is True
    text = dumpf.read_text()
    assert "jane.doe@gmail.com" not in text and "owner=<email>" in text
    assert "    User 0:\n      ceDataInode=12345" in text

    dump = parse_dump.AndroidDump(str(dumpf))
    assert dump.all_apps() == ["com.example.spy"]
    assert dump.info("com.example.spy")["firstInstallTime"] == "2026-09-01 12:00:00"
