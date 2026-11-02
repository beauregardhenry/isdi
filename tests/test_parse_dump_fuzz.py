"""Damaged and unexpected dumps must not crash a scan.

Fuzzing found that a cut-off Android dump crashed the scan (#71). The same
check on the iOS parser found:

- an unreadable iOS dump (cut off, empty, or with stray text from
  pymobiledevice3 in it) crashed `device_info` with KeyError, so staff saw
  the scan fail with the message "'DeviceClass'";
- an entitlement value that is a string was split into characters, each
  shown as a permission; one that holds non-strings lost the app its
  details. Entitlements come from the app's own signature, so an app
  controls them.

The randomized tests at the end damage the fixture dumps in many seeded
ways and check that every public method still returns.
"""

import copy
import json
import logging
import random
from pathlib import Path

import pytest

from isdi.scanner import parse_dump as pd

FIXTURES = Path(__file__).parent / "fixtures"
IOS_TEXT = (FIXTURES / "ios_dump.json").read_text()
IOS = json.loads(IOS_TEXT)
ANDROID_TEXT = (FIXTURES / "android_dump.txt").read_text()
FIRST = next(iter(IOS["apps"]))


def _ios(tmp_path, data, name="dump.json"):
    p = tmp_path / name
    p.write_text(data if isinstance(data, str) else json.dumps(data))
    return pd.IosDump(str(p))


def _exercise_ios(dump):
    """Everything a scan and the app pages call on an iOS dump."""
    ids = dump.installed_apps()
    dump.installed_apps_titles()
    dump.system_apps()
    name, info = dump.device_info()
    assert isinstance(name, str) and isinstance(info, dict)
    assert isinstance(dump.appinfo, list)  # read by the jailbreak check
    for appid in ids or [FIRST]:
        dump.info(appid)
    return ids


# --- unreadable iOS dumps ----------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        IOS_TEXT[: len(IOS_TEXT) // 2],
        "",
        '{"apps": Downloading developer disk image...\n{}, "devinfo": {}}',
        "[]",
        "null",
    ],
    ids=["cut-off", "empty", "stray-text", "list", "null"],
)
def test_an_unreadable_ios_dump_is_an_unknown_phone_with_no_apps(tmp_path, text):
    dump = _ios(tmp_path, text)
    assert _exercise_ios(dump) == []
    # No apps makes the scan page say the scan failed, not that the phone
    # is clean (test_scan_routes.test_failed_scan_is_reported).
    assert dump.device_info()[0] == "Unknown iOS Device"


@pytest.mark.parametrize("devinfo", [None, [], "x", 1, {}], ids=repr)
def test_missing_device_details_keep_the_apps(tmp_path, devinfo):
    data = copy.deepcopy(IOS)
    if devinfo is None:
        del data["devinfo"]
    else:
        data["devinfo"] = devinfo
    dump = _ios(tmp_path, data)
    assert FIRST in _exercise_ios(dump)
    assert dump.device_info()[0] == "Unknown iOS Device"


@pytest.mark.parametrize("apps", [None, "x", 1], ids=repr)
def test_an_apps_section_of_the_wrong_type_has_no_apps(tmp_path, apps):
    data = copy.deepcopy(IOS)
    data["apps"] = apps
    dump = _ios(tmp_path, data)
    assert _exercise_ios(dump) == []
    assert "iOS" in dump.device_info()[0]  # the phone itself is still known


def test_app_entries_that_are_not_dicts_are_skipped(tmp_path):
    data = copy.deepcopy(IOS)
    data["apps"]["bad.none"] = None
    data["apps"]["bad.str"] = "x"
    data["apps"]["bad.list"] = []
    ids = _exercise_ios(_ios(tmp_path, data))
    assert FIRST in ids and not any(i.startswith("bad.") for i in ids)


@pytest.mark.parametrize("kind", [None, 1, [], {}], ids=repr)
def test_an_odd_application_type_does_not_lose_the_app(tmp_path, kind):
    data = copy.deepcopy(IOS)
    data["apps"][FIRST]["ApplicationType"] = kind
    dump = _ios(tmp_path, data)
    assert dump.info(FIRST)["title"]


# --- entitlements written by the app ---------------------------------------------


def _permissions(tmp_path, value):
    data = copy.deepcopy(IOS)
    data["apps"][FIRST]["ApplicationType"] = "User"
    data["apps"][FIRST]["Entitlements"] = {"com.apple.private.tcc.allow": value}
    return [p for p, _ in _ios(tmp_path, data).info(FIRST)["permissions"]]


def test_one_entitlement_as_a_string_is_one_permission(tmp_path):
    perms = _permissions(tmp_path, "kTCCServiceCamera")
    assert len(perms) == 1 and len(perms[0]) > 1


def test_non_string_entitlement_values_are_ignored(tmp_path):
    perms = _permissions(tmp_path, [None, 1, {"x": 1}, "", "kTCCServiceCamera"])
    assert len(perms) == 1 and len(perms[0]) > 1


@pytest.mark.parametrize("value", [None, 1, {"x": 1}], ids=repr)
def test_an_entitlement_of_the_wrong_type_gives_no_permissions(tmp_path, value):
    assert _permissions(tmp_path, value) == []


# --- randomized damage -------------------------------------------------------------

CASES = 300


def _odd_value(rng):
    return rng.choice(
        [None, 0, -1, 1.5, True, "", "x", "\x00", [], {}, [None], {"": None}]
    )


def _damage_json(rng, node, depth=0):
    """Replace some values in a copy of the dump with values of other types."""
    if isinstance(node, dict):
        out = {}
        for k, v in node.items():
            roll = rng.random()
            if roll < 0.05:
                continue  # drop the key
            out[k] = _odd_value(rng) if roll < 0.15 else _damage_json(rng, v, depth + 1)
        if rng.random() < 0.05:
            out[rng.choice(["Entitlements", "ApplicationType", "x"])] = _odd_value(rng)
        return out
    if isinstance(node, list):
        return [
            _odd_value(rng) if rng.random() < 0.15 else _damage_json(rng, v)
            for v in node
        ]
    return node


def _damage_text(rng, text):
    """Cut, delete, duplicate or corrupt parts of a text dump."""
    kind = rng.randrange(5)
    if kind == 0:
        return text[: rng.randrange(len(text) + 1)]
    lines = text.splitlines(keepends=True)
    if kind == 1:
        i = rng.randrange(len(lines))
        del lines[i : i + rng.randint(1, 5)]
    elif kind == 2:
        i = rng.randrange(len(lines))
        lines.insert(rng.randrange(len(lines)), lines[i])
    elif kind == 3:
        i = rng.randrange(len(lines))
        line = lines[i]
        lines[i] = (
            line[: rng.randrange(len(line) + 1)]
            + rng.choice(["", "\t", "  ", ":", "[", "\x00", "é"])
            + "\n"
        )
    else:
        i = rng.randrange(len(lines))
        lines[i] = " " * rng.randint(0, 8) + lines[i].lstrip()
    return "".join(lines)


@pytest.fixture
def quiet():
    logging.disable(logging.CRITICAL)
    yield
    logging.disable(logging.NOTSET)


def test_randomly_damaged_ios_dumps_do_not_crash(tmp_path, quiet):
    rng = random.Random(20261101)
    for i in range(CASES):
        if rng.random() < 0.3:
            text = _damage_text(rng, IOS_TEXT)
        else:
            text = json.dumps(_damage_json(rng, IOS))
        try:
            _exercise_ios(_ios(tmp_path, text, f"{i}.json"))
        except Exception as e:  # pragma: no cover - the failure message
            raise AssertionError(f"case {i} crashed: {e!r}\n{text[:2000]}") from e


def test_randomly_damaged_android_dumps_do_not_crash(tmp_path, quiet):
    rng = random.Random(20261101)
    for i in range(CASES):
        text = _damage_text(rng, ANDROID_TEXT)
        p = tmp_path / f"{i}.txt"
        p.write_text(text)
        try:
            dump = pd.AndroidDump(str(p))
            ids = dump.all_apps()
            dump.system_apps()
            dump.offstore_apps()
            dump.not_installed_for_owner()
            for appid in ids:
                dump.info(appid)
        except Exception as e:  # pragma: no cover - the failure message
            raise AssertionError(f"case {i} crashed: {e!r}\n{text}") from e
