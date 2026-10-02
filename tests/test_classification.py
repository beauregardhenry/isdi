"""Spyware classification: blocklist flags, scores and highlight classes.

Until these tests existed, every flag from app-flags.csv was dropped before
reaching the scan results, so known stalkerware showed up unflagged.
"""

import csv

import pytest

from isdi.config import get_config
from isdi.scanner import blocklist


def _csv_rows():
    with open(get_config().APP_FLAGS_FILE, encoding="latin1", newline="") as f:
        return list(csv.DictReader(f))


def _classify(appids, **kwargs):
    res = blocklist.app_title_and_flag([{"appId": a} for a in appids], **kwargs)
    return {r["appId"]: r for r in res}


@pytest.mark.parametrize("flag", ["stalkerware", "spyware", "dual-use"])
def test_every_blocklisted_app_keeps_its_flag(flag):
    ids = [r["appId"] for r in _csv_rows() if r["flag"] == flag]
    assert ids, f"no {flag} rows in app-flags.csv"
    res = _classify(ids)
    missing = [a for a in ids if flag not in res[a]["flags"]]
    assert (
        not missing
    ), f"{len(missing)} {flag} apps lost their flag, e.g. {missing[:3]}"


@pytest.mark.parametrize("flag", ["stalkerware", "spyware"])
def test_known_spyware_gets_top_score_and_class(flag):
    ids = [r["appId"] for r in _csv_rows() if r["flag"] == flag]
    for appid, r in _classify(ids).items():
        assert blocklist.score(r["flags"]) >= 1.0, appid
        assert blocklist.assign_class(r["flags"]) == "alert-primary", appid


def test_blocklist_title_is_used():
    row = next(r for r in _csv_rows() if r["flag"] == "stalkerware" and r["title"])
    assert _classify([row["appId"]])[row["appId"]]["title"] == row["title"]


def test_unknown_app_gets_no_flags():
    res = _classify(["org.example.calculator"])
    assert res["org.example.calculator"]["flags"] == []
    assert blocklist.score([]) == 0
    assert blocklist.assign_class([]) == ""


def test_offstore_and_system_flags_only_apply_to_listed_apps():
    res = _classify(
        ["org.example.a", "org.example.b", "org.example.c"],
        offstore_apps=["org.example.a"],
        system_apps=["org.example.b"],
    )
    assert res["org.example.a"]["flags"] == ["offstore-app"]
    assert res["org.example.b"]["flags"] == ["system-app"]
    assert res["org.example.c"]["flags"] == []


@pytest.mark.parametrize(
    "appid, flagged",
    [
        ("com.example.phonetracker", True),
        ("com.example.keylogger", True),
        ("com.example.antispyware", False),
        ("com.example.spyware.removal", False),
    ],
)
def test_regex_flag(appid, flagged):
    assert ("regex-spy" in _classify([appid])[appid]["flags"]) is flagged


def test_duplicate_input_is_reported_once():
    res = blocklist.app_title_and_flag(
        [{"appId": "org.example.a"}, {"appId": "org.example.a"}]
    )
    assert [r["appId"] for r in res] == ["org.example.a"]


@pytest.mark.parametrize(
    "flags, cls",
    [
        ([], ""),
        (["system-app"], ""),
        (["regex-spy"], "alert-info"),
        (["dual-use"], "alert-warning"),
        (["offstore-app"], "alert-warning"),
        (["stalkerware"], "alert-primary"),
        (["spyware"], "alert-primary"),
        (["device-owner"], "alert-primary"),
        (["dual-use", "regex-spy"], "alert-primary"),
    ],
)
def test_assign_class_thresholds(flags, cls):
    assert blocklist.assign_class(flags) == cls


def test_flag_str_highlights_spyware_flags():
    html = blocklist.flag_str(["stalkerware", "dual-use", "regex-spy"])
    assert (
        '<span class="text-primary"><abbr title="This app is listed as stalkerware'
        in html
    )
    assert '<span class="text-warning">' in html
    assert '<span class="text-info">' in html
