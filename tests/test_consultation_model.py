"""The questionnaire, device and app risk rules, and the round trip through
the stored dicts. Ported from Sherloc with its rules; the changes are marked."""

import pytest

from isdi.consultation.model import (
    AppInfo,
    Consultation,
    DeviceCheck,
    TAQData,
)


def _risks(report):
    return [r.risk for r in report.risk_details]


# --- questionnaire -------------------------------------------------------------


@pytest.mark.parametrize(
    "answers,expected",
    [
        ({"live_together": "yes"}, ["Physical access to devices"]),
        ({"physical_access": "yes"}, ["Physical access to devices"]),
        ({"purchase_device": "yes"}, ["Physical access to devices"]),
        ({"physical_access": "unsure"}, []),
        ({}, []),
    ],
)
def test_taq_device_access(answers, expected):
    assert _risks(TAQData(devices=answers).devices.generate_risk_report()) == expected


def test_a_known_unlock_code_is_added_to_the_description():
    risk = TAQData(devices={"physical_access": "yes", "device_pin": "yes"}).all_risks[0]
    assert "unlock the device" in risk.description


def test_taq_risks_are_collected_in_section_order():
    taq = TAQData(
        devices={"live_together": "yes"},
        accounts={"pwd_comp": "yes"},
        sharing={"share_phone_plan": "yes", "share_accounts": "yes"},
        smarthome={"smart_home_acct_linking": "yes"},
        kids={"child_phys_access": "yes", "child_phone_plan": "yes"},
        legal={"legal": ["ro"]},
    )
    assert [r.risk for r in taq.all_risks] == [
        "Physical access to devices",
        "Password compromise",
        "Shared phone plan",
        "Shared accounts",
        "Online access to smart home devices",
        "Physical access to children's devices",
        "Shared phone plan (child)",
    ]


def test_smart_home_set_up_by_the_person_of_concern_is_a_risk():
    # A multiple-choice answer, so a list. Sherloc compared it with "poc"
    # and never reported this.
    taq = TAQData(smarthome={"smart_home_setup": ["poc"]})
    risk = taq.smarthome.generate_risk_report().risk_details[0]
    assert risk.risk == "Physical access to smart home devices"
    assert "initially set up" in risk.description


def test_smart_home_physical_access_alone_is_a_risk():
    taq = TAQData(smarthome={"smart_home_setup": ["me"], "smart_home_access": "yes"})
    assert _risks(taq.smarthome.generate_risk_report()) == [
        "Physical access to smart home devices"
    ]


def test_an_empty_questionnaire_has_no_risks():
    assert TAQData().all_risks == []


def test_the_questionnaire_round_trips():
    taq = TAQData(
        marked_done=True,
        devices={"live_together": "yes"},
        legal={"legal": ["ro", "cl"]},
    )
    again = TAQData(**taq.to_dict())
    assert again.marked_done is True
    assert again.devices.live_together == "yes"
    assert again.legal.legal == ["ro", "cl"]


# --- apps ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "flags,expected",
    [
        (["spyware"], "Spyware application"),
        # ISDi's flag for the stalkerware-indicators list. Sherloc's list did
        # not have it, so these apps were not reported as spyware.
        (["stalkerware"], "Spyware application"),
        (["offstore-spyware", "regex-spy"], "Spyware application"),
        (["regex-spy"], "Potential spyware application"),
        (["dual-use"], None),
        ([], None),
    ],
)
def test_app_flag_risk(flags, expected):
    risk = AppInfo(appId="com.x", flags=flags).flag_risk()
    assert (risk.risk if risk else None) == expected


@pytest.mark.parametrize(
    "install,expected",
    [
        ({"knew_installed": "no"}, "did not know"),
        ({"installed": "no"}, "did not install"),
        ({"coerced": "yes"}, "coerced"),
        ({"knew_installed": "unsure"}, None),
    ],
)
def test_app_installed_without_permission(install, expected):
    report = AppInfo(appId="com.x", install_info=install).generate_risk_report()
    found = [
        r.description
        for r in report.risk_details
        if r.risk == "App installed without permission"
    ]
    assert (expected in found[0]) if expected else found == []


def test_a_system_app_is_not_reported_as_installed_without_permission():
    app = AppInfo(appId="com.x", flags=["system-app"], install_info={"installed": "no"})
    assert app.generate_risk_report().risk_details == []


def test_data_leakage():
    app = AppInfo(appId="com.x", permission_info={"access": "yes"})
    assert _risks(app.generate_risk_report()) == ["Data leakage"]


def test_an_app_added_by_hand_is_named_by_its_title():
    app = AppInfo(title="Hidden Tracker", flags=["spyware", ""])
    assert app.title == "Hidden Tracker" and app.appId == ""
    assert app.flags == ["spyware"]


def test_an_app_without_a_title_is_named_by_its_id():
    assert AppInfo(appId="com.x", title="  ").title == "com.x"


def test_permissions_given_alone_are_kept_with_the_answers():
    app = AppInfo(appId="com.x", permissions=["Camera"])
    assert app.permission_info.permissions == ["Camera"]
    assert AppInfo(**app.to_dict()).permission_info.permissions == ["Camera"]


# --- devices -------------------------------------------------------------------


def test_a_device_lists_each_concerning_app():
    device = DeviceCheck(
        scanid=4,
        selected_apps=[
            {"appId": "com.spy", "title": "Spy", "flags": ["stalkerware"]},
            {"appId": "com.calc", "title": "Calculator"},
        ],
    )
    assert device.key == "scan-4"
    assert _risks(device.risk_report) == ["Risk from app: Spy"]
    assert [a.appId for a in device.concerning_apps] == ["com.spy"]


@pytest.mark.parametrize("rooted", [True, "yes", 1])
def test_a_rooted_device_is_a_risk(rooted):
    assert _risks(
        DeviceCheck(key="manual-1", manual=True, is_rooted=rooted).risk_report
    ) == ["Evidence of jailbreaking"]


@pytest.mark.parametrize("rooted", [False, "no", "", 0, "unsure"])
def test_a_device_not_known_to_be_rooted_is_not(rooted):
    assert DeviceCheck(key="manual-1", is_rooted=rooted).risk_report.risk_details == []


def test_a_device_round_trips():
    device = DeviceCheck(
        scanid=7,
        device_nickname="kitchen phone",
        selected_apps=[
            {"appId": "com.spy", "title": "Spy", "install_info": {"installed": "no"}}
        ],
    )
    again = DeviceCheck(**device.to_dict())
    assert again.key == "scan-7" and again.device_nickname == "kitchen phone"
    assert again.selected_apps[0].install_info.installed == "no"


# --- the whole consultation -----------------------------------------------------


def test_a_consultation_collects_risks_by_part():
    c = Consultation(
        taq={"accounts": {"pwd_comp": "yes"}},
        accounts=[{"account_id": 0, "password_check": {"know": "yes"}}],
        devices=[
            {"scanid": 1, "selected_apps": [{"appId": "a", "flags": ["spyware"]}]}
        ],
        notes={"consultant_notes": "n"},
    )
    risks = c.all_risks()
    assert [r.risk for r in risks["taq"]] == ["Password compromise"]
    assert [r.risk for r in risks["accounts"]] == ["Password compromise"]
    assert [r.risk for r in risks["devices"]] == ["Risk from app: a"]
    assert c.notes.consultant_notes == "n"


def test_an_empty_consultation():
    c = Consultation()
    assert c.accounts == [] and c.devices == []
    assert c.all_risks() == {"taq": [], "accounts": [], "devices": []}


def test_every_question_has_text():
    q = Consultation.questions()
    assert set(q["taq"]) == {
        "devices",
        "accounts",
        "sharing",
        "smarthome",
        "kids",
        "legal",
    }
    assert all(
        text.strip()
        for part in q.values()
        for section in part.values()
        for text in section.values()
    )
