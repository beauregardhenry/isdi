"""The detection scorecard (scripts/scorecard.py), and the invariants it
rests on, which hold for the lists shipped with ISDi."""

import csv
import importlib.util
import sqlite3
from pathlib import Path

import pytest

from isdi.scanner import blocklist

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "scorecard.py"
SIGNER = "AB" * 20


@pytest.fixture(scope="module")
def sc():
    spec = importlib.util.spec_from_file_location("scorecard", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# --- what ISDi ships ---------------------------------------------------------------


def test_every_listed_stalkerware_package_is_flagged():
    """The upstream bug this fork fixed: listed apps that got no flag."""
    listed = [r["appId"] for r in blocklist.APP_FLAGS if r["flag"] == "stalkerware"]
    assert len(listed) > 500
    flagged = blocklist.app_title_and_flag([{"appId": a} for a in listed])
    missing = [a["appId"] for a in flagged if "stalkerware" not in a["flags"]]
    assert missing == []


def test_every_listed_certificate_is_matched():
    assert len(blocklist.STALKERWARE_SIGNERS) > 400
    for sha1, app in blocklist.STALKERWARE_SIGNERS.items():
        assert blocklist.signer_apps({sha1}) == [app]


# --- the scorecard -----------------------------------------------------------------


def _samples(tmp_path, rows):
    p = tmp_path / "samples.csv"
    with p.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["SHA256", "Package Name", "Certificate", "Version", "App"])
        w.writerows(rows)
    return p


@pytest.fixture
def lists(monkeypatch):
    monkeypatch.setattr(blocklist, "STALKERWARE_SIGNERS", {SIGNER: "VendorSpy"})
    monkeypatch.setitem(
        blocklist._FLAGS_BY_APPID,
        "com.vendor.spy",
        {"appId": "com.vendor.spy", "flag": "stalkerware", "title": "VendorSpy"},
    )


def test_samples(sc, tmp_path, lists):
    p = _samples(
        tmp_path,
        [
            ["h1", "com.vendor.spy", SIGNER, "1", "VendorSpy"],  # both
            ["h2", "com.vendor.spy", "", "1", "VendorSpy"],  # package
            ["h3", "com.renamed", SIGNER.lower(), "1", "VendorSpy"],  # signer
            ["h4", "com.unknown", "CD" * 20, "1", "Other"],  # missed
            ["h5", "com.phone.tracker", "", "1", "Other"],  # name pattern
            ["h6", "", "", "", "Other"],  # hash only
        ],
    )
    r = sc.samples(p)
    assert r == {
        "total": 6,
        "with_identifiers": 5,
        "by_package": 2,
        "by_signer": 2,
        "by_either": 3,
        "signer_only": 1,
        "name_pattern_only": 1,
        "missed": 1,
        "missed_packages": ["com.unknown"],
    }


def _catalog(tmp_path, rows):
    p = tmp_path / "app-info.db"
    con = sqlite3.connect(p)
    con.execute("create table apps (appId text, title text, store text, relevant text)")
    con.executemany("insert into apps values (?, ?, ?, ?)", rows)
    con.commit()
    con.close()
    return p


def test_catalog(sc, tmp_path, lists):
    p = _catalog(
        tmp_path,
        [
            ("com.vendor.spy", "VendorSpy", "playstore", "y"),
            ("com.whatsapp", "WhatsApp", "playstore", None),
            ("com.routes", "GPS Route Finder Tracker", "playstore", "n"),
            ("com.notes", "Notes", "playstore", "n"),
            ("com.cam", "Spy Camera", "appstore", "y"),
        ],
    )
    r = sc.catalog(p)
    assert r["apps"] == {"appstore": 1, "playstore": 4}
    assert r["known_monitoring"] == {"playstore": 1}
    assert r["name_pattern"] == {"appstore": 1, "playstore": 2}
    assert r["name_pattern_on_not_relevant"] == {"labelled": 2, "flagged": 1}
    assert r["name_pattern_examples"] == ["GPS Route Finder Tracker"]


def test_markdown_and_gate(sc, tmp_path, lists):
    s = sc.samples(_samples(tmp_path, [["h", "com.vendor.spy", SIGNER, "", "V"]]))
    c = sc.catalog(_catalog(tmp_path, [("com.x", "X", "playstore", None)]))
    report = sc.report(s, c)
    md = sc.markdown(report)
    assert "## Detection scorecard" in md
    assert "1 of 1" in md
    assert report["list"]["packages_flagged"] == report["list"]["packages"]
    assert sc.regressions(report) == []
    report["list"]["packages_flagged"] -= 1
    assert sc.regressions(report)


def test_main_writes_markdown_and_json(sc, tmp_path, lists):
    s = _samples(tmp_path, [["h", "com.vendor.spy", "", "", "V"]])
    c = _catalog(tmp_path, [("com.x", "X", "playstore", None)])
    md, js = tmp_path / "out.md", tmp_path / "out.json"
    code = sc.main(
        [
            "--samples",
            str(s),
            "--app-info",
            str(c),
            "--markdown",
            str(md),
            "--json",
            str(js),
        ]
    )
    assert code == 0
    assert md.read_text().startswith("## Detection scorecard")
    assert '"samples"' in js.read_text()
