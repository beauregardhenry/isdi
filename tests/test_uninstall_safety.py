"""Uninstalling runs a command on the phone with an app id and serial that
come from the web form. Hostile values must be refused before any command
runs, and must stay inert even if they got past the route."""

import pytest

import isdi.scanner as scanner
from tests.test_scanner_pipeline import FAKE_ADB, SERIAL, _fake_tool
from tests.test_web_flows import fake_phone, stored_scan  # noqa: F401

HOSTILE = [
    "com.x; touch /tmp/pwned",
    "com.x && reboot",
    "$(reboot)",
    "`reboot`",
    "com.x\nreboot",
    "com.x|sh",
    "../../etc/passwd",
    "-k com.x",  # an adb option, not an app
    "",
]


@pytest.mark.parametrize("appid", HOSTILE)
def test_the_route_refuses_hostile_app_ids(
    no_csrf, fake_phone, client, stored_scan, appid  # noqa: F811
):
    r = client.post(
        f"/delete/app/{stored_scan}", data={"serial": "REALSERIAL1", "appid": appid}
    )
    assert r.status_code == 400
    assert fake_phone == [], "the phone was asked to uninstall"


@pytest.mark.parametrize(
    "serial", ["REALSERIAL1; reboot", "$(id)", "-s other", "a b", "", "x" * 300]
)
def test_the_route_refuses_hostile_serials(
    no_csrf, fake_phone, client, stored_scan, serial  # noqa: F811
):
    r = client.post(
        f"/delete/app/{stored_scan}",
        data={"serial": serial, "appid": "com.example.mdm"},
    )
    assert r.status_code == 400
    assert fake_phone == []


def test_a_hostile_app_id_stays_inert_in_the_adb_command(tmp_path):
    """Defence in depth: should a value ever get past the route, the
    command quotes it, so the shell never runs any part of it."""
    marker = tmp_path / "ran"
    sc = scanner.AndroidScanner()
    sc.cli = _fake_tool(tmp_path, "adb", FAKE_ADB)
    assert sc.uninstall(SERIAL, f"com.x; touch {marker}") is False
    assert sc.uninstall(SERIAL, f"$(touch {marker})") is False
    assert not marker.exists()


def test_a_hostile_app_id_stays_inert_in_the_ios_command(tmp_path):
    marker = tmp_path / "ran"
    sc = scanner.IosScanner()
    sc.cli = _fake_tool(tmp_path, "pmd3", "import sys; print('failed')")
    assert sc.uninstall("00008110-000A1B2C3D4E5F", f"com.x; touch {marker}") is False
    assert not marker.exists()
