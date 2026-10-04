"""Dump parsing on layouts and values the fixture dumps do not have: a
misread here silently drops an app or a detail from the scan."""

import shutil
from pathlib import Path

import pytest

from isdi.scanner import parse_dump as pd

FIXTURES = Path(__file__).parent / "fixtures"


def _android(df):
    """An AndroidDump over an already-parsed dump."""
    d = pd.AndroidDump.__new__(pd.AndroidDump)
    d.device_type, d.dumpf, d.df, d.apps = "android", "x.txt", df, None
    return d


def test_each_dump_is_parsed_once(tmp_path, monkeypatch):
    calls = []
    original = pd.AndroidDump.new_parse_dump_file
    monkeypatch.setattr(
        pd.AndroidDump,
        "new_parse_dump_file",
        lambda self, f: calls.append(f) or original(self, f),
    )
    shutil.copy(FIXTURES / "android_dump.txt", tmp_path / "x.txt")
    pd.AndroidDump(str(tmp_path / "x.txt"))
    assert len(calls) == 1

    reads = []
    original_ios = pd.IosDump.load_file
    monkeypatch.setattr(
        pd.IosDump, "load_file", lambda self: reads.append(1) or original_ios(self)
    )
    shutil.copy(FIXTURES / "ios_dump.json", tmp_path / "i.json")
    pd.IosDump(str(tmp_path / "i.json"))
    assert len(reads) == 1


def test_sections_odd_lines_and_unparsable_parts(tmp_path, caplog, monkeypatch):
    def boom(lines):
        raise IndentationError("bad")

    monkeypatch.setattr(pd, "complexparse", boom)
    dump = tmp_path / "d.txt"
    dump.write_text(
        "----------\n"
        "DUMP OF SERVICE netstats detail\n"
        "  a: 1\n"
        "DUMP OF SERVICE net_stats\n"
        "DUMP OF SETTINGS secure\n"
        "x=1\n"
    )
    d = _android(None).new_parse_dump_file(str(dump))
    assert set(d) == {"net_stats", "secure"}
    # The netstats detail section is kept though an empty net_stats follows.
    assert d["net_stats"] == {"UNPARSED": ["  a: 1\n"]}
    assert "Could not parse service" in caplog.text and "a: 1" not in caplog.text


def test_procstats():
    text = (
        "  * com.example / u0a12 / v34:\n"
        "      TOTAL: 2.5% (10MB-20MB-30MB/0.00-0.00-0.00/1MB-1MB-1MB over 4)\n"
        "  ignored line\n"
    )
    apps = pd.parse_procstats(text)
    stats = apps["com.example"]
    assert stats["uid"] == "u0a12" and stats["version"] == "v34"
    assert stats["stats"]["TOTAL"]["percent"] == "2.5%"
    assert stats["stats"]["TOTAL"]["ram"] == ["10MB", "20MB", "30MB"]
    assert stats["stats"]["TOTAL"]["samples"] == 4


NET = {
    "net_stats": [
        {
            "BPF map content": {
                "mUidCounterSetMap": [{"10012": "10012 1"}],
                "mAppUidStatsMap": [
                    "10012 1048576 3 1048576 4",
                    "10013 1 2 3",
                ],
            }
        }
    ]
}


@pytest.mark.parametrize(
    "uid, used, background",
    [
        ("u0a12", "2.00 MB", "yes"),  # u0aN is uid 10000 + N
        ("10013", "unknown", "unknown"),  # malformed row
        ("10099", "unknown", "unknown"),  # not listed
    ],
)
def test_data_usage(uid, used, background):
    import copy

    res = pd.AndroidDump.get_data_usage(copy.deepcopy(NET), "app", uid)
    assert res == {"data_used": used, "background_data_allowed": background}


def test_data_usage_without_net_stats():
    assert pd.AndroidDump.get_data_usage({}, "app", "10012")["data_used"] == "unknown"


@pytest.mark.parametrize(
    "line, expected",
    [("Uid u0a12: 4.2 ( cpu=4.2 )", " 4.2 ( cpu=4.2 )"), ("Uid u0a12 4.2", "unknown")],
)
def test_battery_use(monkeypatch, line, expected):
    monkeypatch.setattr(pd, "match_keys", lambda d, keys: {"x": [line]})
    assert pd.AndroidDump.get_battery_stat({}, "app", "u0a12") == expected


def test_no_battery_use():
    assert pd.AndroidDump.get_battery_stat({}, "app", "u0a12") == "0 (mAh)"


@pytest.mark.parametrize(
    "df",
    [{}, {"other": {}}, {"package": [{"Not packages": 1}]}],
)
def test_dumps_without_packages_have_no_apps(df):
    dump = _android(df)
    assert dump.all_apps() == [] and dump.info("com.x") == {}


def test_packages_section_variants():
    df = {
        "package": [
            {"Something else": 1},
            {
                "Packages": {
                    "Package [com.a] (1a2b)": {
                        "flags": ["[ SYSTEM HAS_CODE ]"],
                        "User 0": [{"firstInstallTime": "2026-01-01"}],
                    },
                    "Package [com.b] (3c4d)": {
                        "flags": "[ HAS_CODE ]",
                        "firstInstallTime": "2026-02-02",
                        "installerPackageName": "com.android.vending",
                    },
                    "not a package line": {},
                }
            },
        ]
    }
    dump = _android(df)
    assert dump.all_apps() == ["com.a", "com.b"]
    assert dump.system_apps() == ["com.a"]
    assert dump.apps["com.a"]["firstInstallTime"] == "2026-01-01"
    assert dump.offstore_apps() == []  # com.a is a system app, com.b from Play
    assert dump.info("com.missing") == {}


def test_match_keys_and_retrieve_tolerate_odd_shapes(caplog):
    assert pd.match_keys("not a dict", "a//b") == {}
    assert pd.match_keys("not a dict", "a") == []
    assert pd.match_keys([{"ab": 1, "c": 2}], "a.*") == ["ab"]
    assert pd.match_keys({"a": 1}, "a//b") == {"a": {}}
    assert pd.retrieve({"a": {"b": "x"}}, ["a", "b"]) == "x"
    assert pd.retrieve({"a": {}}, ["a", "b"]) == ""
    assert pd.retrieve({"a": 1}, ["a", "b"]) == ""
    assert "KeyError" in caplog.text and "TypeError" in caplog.text
