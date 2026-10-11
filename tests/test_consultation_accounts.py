"""The account risk rules decide which findings appear in the consultation report.

Ported from Sherloc's tests with the rules.

These tests pin each rule. Answers come from the form's choices: "yes", "no",
"unsure", or "" when the question was skipped. An "unsure" answer never
produces a risk today; whether it should is a question for consultants, so
the tests record the current behaviour without endorsing it.
"""

import pytest

from isdi.consultation.model import (
    AccountInvestigation,
    PasswordCheck,
    RecoverySettings,
    SecurityQuestions,
    SuspiciousLogins,
    TwoFactorSettings,
)


def _risks(section):
    return [r.risk for r in section.generate_risk_report().risk_details]


# --- suspicious logins ----------------------------------------------------------


@pytest.mark.parametrize(
    "recognize,activity,expected",
    [
        ("yes", "yes", ["Unrecognized devices", "Suspicious logins"]),
        ("yes", "no", ["Unrecognized devices"]),
        ("no", "yes", ["Suspicious logins"]),
        ("no", "no", []),
        ("unsure", "unsure", []),
        ("", "", []),
    ],
)
def test_suspicious_logins(recognize, activity, expected):
    assert (
        _risks(SuspiciousLogins({"recognize": recognize, "activity_log": activity}))
        == expected
    )


# --- password ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "know,guess,federated_comp,expected",
    [
        ("yes", "no", "no", ["Password compromise"]),
        # Knowing the password already covers guessing it: only one is listed.
        ("yes", "yes", "no", ["Password compromise"]),
        ("no", "yes", "no", ["Potential password compromise"]),
        ("unsure", "yes", "no", ["Potential password compromise"]),
        ("no", "no", "yes", ["Compromised federated account"]),
        ("yes", "no", "yes", ["Password compromise", "Compromised federated account"]),
        ("no", "no", "no", []),
        ("unsure", "unsure", "unsure", []),
        ("", "", "", []),
    ],
)
def test_password(know, guess, federated_comp, expected):
    section = PasswordCheck(
        {"know": know, "guess": guess, "federated_comp": federated_comp}
    )
    assert _risks(section) == expected


# --- recovery settings ------------------------------------------------------------


@pytest.mark.parametrize(
    "phone_access,email_access,expected",
    [
        ("yes", "no", ["Compromised recovery information"]),
        ("no", "yes", ["Compromised recovery information"]),
        # Both compromised is still one finding, not two.
        ("yes", "yes", ["Compromised recovery information"]),
        ("no", "no", []),
        ("unsure", "unsure", []),
    ],
)
def test_recovery_settings(phone_access, email_access, expected):
    section = RecoverySettings(
        {"phone_access": phone_access, "email_access": email_access}
    )
    assert _risks(section) == expected


# --- two-factor -------------------------------------------------------------------


@pytest.mark.parametrize(
    "enabled,access,expected",
    [
        ("yes", "yes", ["Compromised second factor"]),
        ("yes", "no", []),
        ("no", "", ["Two-factor authentication disabled"]),
        ("no", "no", ["Two-factor authentication disabled"]),
        # A compromised second factor is reported even if "enabled" was not answered.
        ("", "yes", ["Compromised second factor"]),
        ("unsure", "unsure", []),
        ("", "", []),
    ],
)
def test_two_factor(enabled, access, expected):
    section = TwoFactorSettings({"enabled": enabled, "second_factor_access": access})
    assert _risks(section) == expected


# --- security questions -------------------------------------------------------------


@pytest.mark.parametrize(
    "present,know,expected",
    [
        ("yes", "yes", ["Guessable security questions"]),
        ("yes", "no", ["Use of security questions"]),
        ("yes", "unsure", ["Use of security questions"]),
        ("no", "yes", []),
        ("", "", []),
    ],
)
def test_security_questions(present, know, expected):
    assert _risks(SecurityQuestions({"present": present, "know": know})) == expected


# --- the whole account ----------------------------------------------------------------


def test_an_account_lists_every_section_risk_in_order():
    account = AccountInvestigation(
        account_id=3,
        platform="Example Mail",
        username="client@example.com",
        suspicious_logins={"recognize": "yes"},
        password_check={"know": "yes"},
        recovery_settings={"email_access": "yes"},
        two_factor_settings={"enabled": "no"},
        security_questions={"present": "yes", "know": "yes"},
    )
    assert [r.risk for r in account.risk_report.risk_details] == [
        "Unrecognized devices",
        "Password compromise",
        "Compromised recovery information",
        "Two-factor authentication disabled",
        "Guessable security questions",
    ]


def test_an_account_with_no_answers_has_no_risks():
    assert AccountInvestigation(account_id=0).risk_report.risk_details == []


def test_every_risk_has_a_description():
    account = AccountInvestigation(
        suspicious_logins={"recognize": "yes", "activity_log": "yes"},
        password_check={"know": "yes", "federated_comp": "yes"},
        recovery_settings={"phone_access": "yes"},
        two_factor_settings={"second_factor_access": "yes"},
        security_questions={"present": "yes", "know": "no"},
    )
    assert account.risk_report.risk_details
    assert all(r.description.strip() for r in account.risk_report.risk_details)
