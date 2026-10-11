"""What is recorded in a consultation, and the risks it shows.

Each part (the questionnaire, an account, a device and its apps) is built
from the plain dict stored for it (store.py) and turned back into one with
to_dict(). generate_risk_report() lists the risks the answers point to; the
report prints them. The rules are Sherloc's, unchanged except where noted.

Answers are the form's codes: "yes", "no", "unsure", or "" when a question
was skipped. An "unsure" answer never produces a risk; whether it should is
a question for the people who run consultations.
"""

import json
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Sequence

# Flags that mean the app is known to be built for monitoring. "stalkerware"
# is what ISDi's blocklist gives the stalkerware-indicators list; Sherloc's
# list did not have it.
SPYWARE_FLAGS = {"spyware", "stalkerware", "onstore-spyware", "offstore-spyware"}


#: Worked out from the answers each time, so never stored.
DERIVED = {"risk_report", "all_risks", "concerning_apps"}


class Dictable:
    def to_dict(self, derived: bool = False) -> Any:
        """The answers as plain data, for storing. With derived, also the
        risks worked out from them (for the report)."""

        def plain(o):
            return {k: v for k, v in o.__dict__.items() if derived or k not in DERIVED}

        return json.loads(json.dumps(self, default=plain))


class DictInitClass(Dictable):
    """A form section: one attribute per question, "" when unanswered."""

    attrs: List[str] = []
    questions: Dict[str, str] = {}

    if TYPE_CHECKING:
        # One attribute per question, set in __init__.
        def __getattr__(self, name: str) -> Any: ...

    def __init__(self, datadict: Optional[dict] = None):
        datadict = datadict or {}
        for k in self.attrs:
            # An empty text field comes from the form as None.
            value = datadict.get(k)
            setattr(self, k, "" if value is None else value)


class Risk(Dictable):
    def __init__(self, risk: str = "", description: str = ""):
        self.risk = risk
        self.description = description


class RiskReport(Dictable):
    def __init__(self, risk_details: Optional[List[Risk]] = None):
        self.risk_details = list(risk_details or [])
        self.risk_present = len(self.risk_details) > 0


def _report(risks: Sequence[Optional[Risk]]) -> RiskReport:
    return RiskReport(risk_details=[r for r in risks if r is not None])


class Notes(DictInitClass):
    attrs = ["client_notes", "consultant_notes"]


# --- the technology assessment questionnaire (TAQ) -------------------------


class TAQDevices(DictInitClass):
    questions = {
        "live_together": "Do you live with the person of concern?",
        "purchase_device": "Did the person of concern purchase and/or set up any of your devices?",
        "purchase_device_which": "Which devices did the person of concern purchase and/or set up?",
        "physical_access": "Has the person of concern had physical access to your devices at any point in time?",
        "physical_access_which": "To which devices has the person of concern had physical access?",
        "device_pin": "Can the person of concern unlock any of these devices with PIN, password, or biometrics?",
    }
    attrs = list(questions)

    def generate_risk_report(self) -> RiskReport:
        risks = []
        if "yes" in (
            self.live_together.lower(),
            self.physical_access.lower(),
            self.purchase_device.lower(),
        ):
            risk = Risk(
                risk="Physical access to devices",
                description="A person with physical access to devices might be able to install apps, adjust device configurations, and access or manipulate accounts logged in on that device.",
            )
            if self.device_pin.lower() == "yes":
                risk.description += " They can also unlock the device with a PIN, password, or biometrics, which would allow them to access all data on the device."
            risks.append(risk)
        self.risk_report = _report(risks)
        return self.risk_report


class TAQAccounts(DictInitClass):
    questions = {
        "pwd_mgmt": "How do you remember your passwords?",
        "pwd_mgmt_describe": "Please provide more details on how you remember your passwords.",
        "pwd_comp": "Do you believe the person of concern knows, or could guess, any of your passwords?",
        "pwd_comp_which": "Which passwords do you believe are compromised, and why?",
    }
    attrs = list(questions)

    def generate_risk_report(self) -> RiskReport:
        risks = []
        if self.pwd_comp == "yes":
            risks.append(
                Risk(
                    risk="Password compromise",
                    description="Someone who knows account passwords may be able to access and/or manipulate those accounts.",
                )
            )
        self.risk_report = _report(risks)
        return self.risk_report


class TAQSharing(DictInitClass):
    questions = {
        "share_phone_plan": "Do you share a phone plan with the person of concern?",
        "phone_plan_admin": "If you share a phone plan, who is the family 'head' or plan administrator?",
        "share_accounts": "Do you share any accounts with the person of concern?",
        "share_which": "Which accounts are shared with the person of concern?",
    }
    attrs = list(questions)

    def generate_risk_report(self) -> RiskReport:
        risks = []
        if self.share_phone_plan == "yes":
            risks.append(
                Risk(
                    risk="Shared phone plan",
                    description="A shared phone plan may leak a variety of information, possibly including call history, message history (but not message content), contacts, and sometimes location. The account administrator of the client's phone plan has even more privileged access to this information.",
                )
            )
        if self.share_accounts == "yes":
            risks.append(
                Risk(
                    risk="Shared accounts",
                    description="The client has shared accounts with the person of concern. Any information on those accounts can be assumed to be known by the person of concern.",
                )
            )
        self.risk_report = _report(risks)
        return self.risk_report


def _chose(answer, code: str) -> bool:
    """A multiple-choice answer (a list of codes) or a single code."""
    return code in answer if isinstance(answer, list) else answer == code


class TAQSmarthome(DictInitClass):
    questions = {
        "smart_home": "Do you have any smart home devices?",
        "smart_home_setup": "Who installed and set up your smart home devices?",
        "smart_home_access": "Did the person of concern ever have physical access to the devices?",
        "smart_home_acct_sharing": "Do you share any smart home accounts with the person of concern?",
        "smart_home_acct_linking": "Can the person of concern access any of the smart home devices via their own smart home account?",
    }
    attrs = list(questions)

    def generate_risk_report(self) -> RiskReport:
        risks = []
        # Sherloc compared this multiple-choice answer (a list) with "poc",
        # so who set the devices up never counted.
        if _chose(self.smart_home_setup, "poc"):
            risks.append(
                Risk(
                    risk="Physical access to smart home devices",
                    description="With physical access to smart home devices, someone could (1) learn private information, for example by querying a smart speaker, or (2) reconfigure the devices to share information or allow remote control. Someone who initially set up the devices would have even more power to configure as they wish.",
                )
            )
        elif self.smart_home_access == "yes":
            risks.append(
                Risk(
                    risk="Physical access to smart home devices",
                    description="With physical access to smart home devices, someone could (1) learn private information, for example by querying a smart speaker, or (2) reconfigure the devices to share information or allow remote control.",
                )
            )
        if "yes" in (self.smart_home_acct_sharing, self.smart_home_acct_linking):
            risks.append(
                Risk(
                    risk="Online access to smart home devices",
                    description="Someone with online access to a smart home device might be able to gather data (e.g., viewing video recordings or voice commands used) or manipulate the device state (e.g., turning a light off or locking a smart lock.)",
                )
            )
        self.risk_report = _report(risks)
        return self.risk_report


class TAQKids(DictInitClass):
    questions = {
        "custody": "If you have children, do they have electronic devices?",
        "child_phys_access": "Has the person of concern had physical access to any of the child(ren)'s devices?",
        "child_phone_plan": "Does the person of concern pay for the child(ren)'s phone plan?",
    }
    attrs = list(questions)

    def generate_risk_report(self) -> RiskReport:
        risks = []
        if self.child_phys_access == "yes":
            risks.append(
                Risk(
                    risk="Physical access to children's devices",
                    description="A person with physical access to children's devices might be able to install apps, adjust device configurations, and access or manipulate accounts logged in on that device. These changes could allow monitoring of the parent, for example by tracking the children's location when they are with their parent.",
                )
            )
        if self.child_phone_plan == "yes":
            risks.append(
                Risk(
                    risk="Shared phone plan (child)",
                    description="A shared phone plan may leak a variety of information, possibly including call history, message history (but not message content), contacts, and sometimes location. This could include information about the parent, such as their phone number and location when with the children. The plan administrator has even more privileged access to this information.",
                )
            )
        self.risk_report = _report(risks)
        return self.risk_report


class TAQLegal(DictInitClass):
    questions = {"legal": "Do you have any ongoing or upcoming legal cases?"}
    attrs = list(questions)

    def generate_risk_report(self) -> RiskReport:
        self.risk_report = _report([])
        return self.risk_report


TAQ_SECTIONS = {
    "devices": TAQDevices,
    "accounts": TAQAccounts,
    "sharing": TAQSharing,
    "smarthome": TAQSmarthome,
    "kids": TAQKids,
    "legal": TAQLegal,
}


class TAQData(Dictable):
    def __init__(self, marked_done: bool = False, **sections):
        self.marked_done = bool(marked_done)
        for name, cls in TAQ_SECTIONS.items():
            setattr(self, name, cls(sections.get(name)))
        self.generate_risk_reports()

    def generate_risk_reports(self) -> List[Risk]:
        self.all_risks: List[Risk] = []
        for name in TAQ_SECTIONS:
            self.all_risks.extend(
                getattr(self, name).generate_risk_report().risk_details
            )
        return self.all_risks


# --- accounts ----------------------------------------------------------------


class AccountSection(DictInitClass):
    #: Screenshots taken for this section are stored under this name.
    screenshot_label = ""


class SuspiciousLogins(AccountSection):
    questions = {
        "recognize": "Do you see any unrecognized devices that are logged into this account?",
        "describe_logins": "Which devices do you not recognize?",
        "activity_log": "In the login history, do you see any suspicious logins?",
        "describe_activity": "Which logins are suspicious, and why?",
    }
    attrs = list(questions)
    screenshot_label = "suspicious_logins"

    def generate_risk_report(self) -> RiskReport:
        risks = []
        if self.recognize == "yes":
            risks.append(
                Risk(
                    risk="Unrecognized devices",
                    description="There are unrecognized devices currently logged into this account.",
                )
            )
        if self.activity_log == "yes":
            risks.append(
                Risk(
                    risk="Suspicious logins",
                    description="There are suspicious logins to this account that do not appear to have come from the client.",
                )
            )
        self.risk_report = _report(risks)
        return self.risk_report


class PasswordCheck(AccountSection):
    questions = {
        "last_updated": "When did you last update this password (approximately)?",
        "know": "Does the person of concern know the password for this account?",
        "guess": "Do you believe the person of concern could guess the password?",
        "federated": "Do you log into this account using a federated login (e.g., Google, Facebook, Apple)?",
        "federated_which": "What other account do you use to log in?",
        "federated_comp": "Do you believe the person of concern has access to the federated account?",
    }
    attrs = list(questions)

    def generate_risk_report(self) -> RiskReport:
        risks = []
        if self.know == "yes":
            risks.append(
                Risk(
                    risk="Password compromise",
                    description="Knowing the password to this account could enable the person of concern to log in. (Note: If two-factor authentication is enabled, they would still need to bypass the second factor.)",
                )
            )
        elif self.guess == "yes":
            risks.append(
                Risk(
                    risk="Potential password compromise",
                    description="The client believes the person of concern could guess the password for this account. If they guess correctly, it would enable them to log in. (Note: If two-factor authentication is enabled, they would still need to bypass the second factor.)",
                )
            )
        if self.federated_comp == "yes":
            risks.append(
                Risk(
                    risk="Compromised federated account",
                    description="By compromising the federated account, the person of concern could log into this account without needing to know the password.",
                )
            )
        self.risk_report = _report(risks)
        return self.risk_report


class RecoverySettings(AccountSection):
    questions = {
        "phone_present": "Is there a recovery phone number set for this account?",
        "phone": "What is the recovery phone number?",
        "phone_access": "Do you believe the person of concern has access to the recovery phone number?",
        "email_present": "Is there a recovery email address set for this account?",
        "email": "What is the recovery email address?",
        "email_access": "Do you believe the person of concern has access to this recovery email address?",
    }
    attrs = list(questions)
    screenshot_label = "recovery_settings"

    def generate_risk_report(self) -> RiskReport:
        risks = []
        if "yes" in (self.phone_access, self.email_access):
            risks.append(
                Risk(
                    risk="Compromised recovery information",
                    description="With access to the recovery contact information, someone can access an account without knowing the password using the 'Forgot password' option.",
                )
            )
        self.risk_report = _report(risks)
        return self.risk_report


class TwoFactorSettings(AccountSection):
    questions = {
        "enabled": "Is two-factor authentication enabled for this account?",
        "second_factor_type": "What type of two-factor authentication is used?",
        "describe": "Which phone/email/app is set as the second factor?",
        "second_factor_access": "Do you believe the person of concern has access to this second factor?",
    }
    attrs = list(questions)
    screenshot_label = "two_factor_settings"

    def generate_risk_report(self) -> RiskReport:
        risks = []
        if self.second_factor_access == "yes":
            risks.append(
                Risk(
                    risk="Compromised second factor",
                    description="If someone has access to the second authentication factor, they only need the account password to log into the account. They could also intercept and delete login notifications.",
                )
            )
        elif self.enabled == "no":
            risks.append(
                Risk(
                    risk="Two-factor authentication disabled",
                    description="Without two-factor authentication, others only need the account password to log in.",
                )
            )
        self.risk_report = _report(risks)
        return self.risk_report


class SecurityQuestions(AccountSection):
    questions = {
        "present": "Does the account use security questions?",
        "know": "Do you believe the person of concern knows the answer to any of these questions?",
        "which": "Which questions might they be able to answer?",
    }
    attrs = list(questions)
    screenshot_label = "security_questions"

    def generate_risk_report(self) -> RiskReport:
        risks = []
        if self.present == "yes":
            if self.know == "yes":
                risks.append(
                    Risk(
                        risk="Guessable security questions",
                        description="The client believes the person of concern knows the answers to security questions, which could allow them an easy way to log into the account.",
                    )
                )
            else:
                risks.append(
                    Risk(
                        risk="Use of security questions",
                        description="The account allows login using security questions, which are not secure because they are easy to guess.",
                    )
                )
        self.risk_report = _report(risks)
        return self.risk_report


ACCOUNT_SECTIONS = {
    "suspicious_logins": SuspiciousLogins,
    "password_check": PasswordCheck,
    "recovery_settings": RecoverySettings,
    "two_factor_settings": TwoFactorSettings,
    "security_questions": SecurityQuestions,
}
#: Sections that can have screenshots, by their screenshot label.
SCREENSHOT_SECTIONS = [
    c.screenshot_label for c in ACCOUNT_SECTIONS.values() if c.screenshot_label
]


class AccountInvestigation(Dictable):
    def __init__(
        self,
        account_id: int = 0,
        platform: str = "",
        username: str = "",
        notes: Optional[dict] = None,
        **sections,
    ):
        self.account_id = int(account_id)
        self.platform = platform
        self.username = username
        for name, cls in ACCOUNT_SECTIONS.items():
            setattr(self, name, cls(sections.get(name)))
        self.notes = Notes(notes)
        self.generate_risk_report()

    def generate_risk_report(self) -> RiskReport:
        risks: List[Risk] = []
        for name in ACCOUNT_SECTIONS:
            risks.extend(getattr(self, name).generate_risk_report().risk_details)
        self.risk_report = _report(risks)
        return self.risk_report


# --- devices and apps ----------------------------------------------------------


class InstallInfo(DictInitClass):
    questions = {
        "knew_installed": "Did you know this app was installed?",
        "installed": "Did you install this app?",
        "coerced": "Did the person of concern coerce you into installing this app?",
    }
    attrs = list(questions)

    def generate_risk_report(self, system_app: bool = False) -> RiskReport:
        risks = []
        if not system_app:
            description = ""
            if self.knew_installed == "no":
                description = "The client did not know this app was installed, indicating someone else installed it."
            elif self.installed == "no":
                description = "The client did not install this app, indicating someone else installed it."
            elif self.coerced == "yes":
                description = "The client was coerced into installing this app."
            if description:
                risks.append(
                    Risk(
                        risk="App installed without permission", description=description
                    )
                )
        self.risk_report = _report(risks)
        return self.risk_report


class PermissionInfo(DictInitClass):
    questions = {
        "access": "Is any information being leaked to the person of concern through this app?",
        "describe": "If yes, please describe.",
    }
    attrs = ["permissions", "access", "describe"]

    def generate_risk_report(self) -> RiskReport:
        risks = []
        if self.access == "yes":
            risks.append(
                Risk(
                    risk="Data leakage",
                    description="This app is sharing data with the person of concern.",
                )
            )
        self.risk_report = _report(risks)
        return self.risk_report


class AppInfo(Dictable):
    """An app on a device, and what the client said about it."""

    def __init__(
        self,
        appId: str = "",
        title: str = "",
        flags: Optional[List[str]] = None,
        investigate: bool = False,
        install_time: str = "",
        app_version: str = "",
        last_updated: str = "",
        permissions: Optional[list] = None,
        permission_info: Optional[dict] = None,
        install_info: Optional[dict] = None,
        notes: Optional[dict] = None,
        **_ignored,
    ):
        self.appId = appId
        # Apps added by hand have no id: the name is all there is.
        self.title = (title or "").strip() or appId
        self.flags = [f for f in (flags or []) if f]
        self.investigate = bool(investigate)
        self.install_time = install_time
        self.app_version = app_version
        self.last_updated = last_updated
        info = dict(permission_info or {})
        info.setdefault("permissions", list(permissions or []))
        self.permission_info = PermissionInfo(info)
        self.install_info = InstallInfo(install_info)
        self.notes = Notes(notes)

    def flag_risk(self) -> Optional[Risk]:
        if SPYWARE_FLAGS & set(self.flags):
            return Risk(
                risk="Spyware application",
                description="This app is designed for covert surveillance.",
            )
        if "regex-spy" in self.flags:
            return Risk(
                risk="Potential spyware application",
                description="This app may be a spyware application based on its title and description.",
            )
        return None

    def generate_risk_report(self) -> RiskReport:
        risks = [self.flag_risk()]
        risks += self.permission_info.generate_risk_report().risk_details
        risks += self.install_info.generate_risk_report(
            system_app="system-app" in self.flags
        ).risk_details
        self.risk_report = _report(risks)
        return self.risk_report


class DeviceCheck(Dictable):
    """A device looked at in the consultation: one of ISDi's scans of this
    client (scanid), or a device added by hand (manual, scanid 0).

    Only the apps chosen for questions are kept here, with the answers; the
    scan itself (every app, its flags, the device details) stays in ISDi's
    scan tables. Sherloc called this ScanData and copied the whole scan."""

    def __init__(
        self,
        key: str = "",
        scanid: int = 0,
        manual: bool = False,
        device_type: str = "",
        device_nickname: str = "",
        device_model: str = "",
        device_version: str = "",
        device_manufacturer: str = "",
        is_rooted: Any = "",
        rooted_reasons: Any = "",
        selected_apps: Optional[List[dict]] = None,
        **_ignored,
    ):
        self.scanid = int(scanid or 0)
        self.manual = bool(manual)
        self.key = key or (f"scan-{self.scanid}" if self.scanid else "")
        self.device_type = device_type
        self.device_nickname = device_nickname
        self.device_model = device_model
        self.device_version = device_version
        self.device_manufacturer = device_manufacturer
        self.is_rooted = is_rooted
        self.rooted_reasons = rooted_reasons
        self.selected_apps = [AppInfo(**a) for a in (selected_apps or [])]
        self.generate_risk_report()

    def generate_risk_report(self) -> RiskReport:
        risks = []
        self.concerning_apps: List[AppInfo] = []
        if self.is_rooted is True or self.is_rooted in ("yes", 1, "1", "True"):
            risks.append(
                Risk(
                    risk="Evidence of jailbreaking",
                    description="The device may be jailbroken, giving the person of concern nearly unbounded access to the device and the client's activity on the device.",
                )
            )
        for app in self.selected_apps:
            report = app.generate_risk_report()
            if report.risk_present:
                self.concerning_apps.append(app)
                risks.append(
                    Risk(
                        risk="Risk from app: {}".format(app.title),
                        description="Risks identified: {}.".format(
                            ", ".join(r.risk for r in report.risk_details)
                        ),
                    )
                )
        self.risk_report = _report(risks)
        return self.risk_report


class ConsultNotes(Dictable):
    def __init__(self, consultant_notes: str = "", client_notes: str = "", **_ignored):
        self.consultant_notes = consultant_notes
        self.client_notes = client_notes


class Consultation(Dictable):
    """Everything recorded for one client, for the overview and the report."""

    def __init__(
        self,
        taq: Optional[dict] = None,
        accounts: Optional[List[dict]] = None,
        devices: Optional[List[dict]] = None,
        notes: Optional[dict] = None,
    ):
        self.taq = TAQData(**(taq or {}))
        self.accounts = [AccountInvestigation(**a) for a in (accounts or [])]
        self.devices = [DeviceCheck(**d) for d in (devices or [])]
        self.notes = ConsultNotes(**(notes or {}))

    def all_risks(self) -> Dict[str, List[Risk]]:
        return {
            "taq": self.taq.generate_risk_reports(),
            "accounts": [
                r for a in self.accounts for r in a.generate_risk_report().risk_details
            ],
            "devices": [
                r for d in self.devices for r in d.generate_risk_report().risk_details
            ],
        }

    @staticmethod
    def questions() -> dict:
        """The question text of every section, for the report."""
        return {
            "taq": {n: c.questions for n, c in TAQ_SECTIONS.items()},
            "accounts": {n: c.questions for n, c in ACCOUNT_SECTIONS.items()},
            "apps": {
                "permission_info": PermissionInfo.questions,
                "install_info": InstallInfo.questions,
            },
        }
