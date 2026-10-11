"""Forms for the consultation pages. The question text comes from model.py,
so the form, the stored answers and the report always match.

Plain WTForms forms, like ISDi's other forms: CSRFProtect checks the token
the templates put in every form, so the sub-forms carry none of their own.
"""

from wtforms import (
    BooleanField,
    FieldList,
    Form,
    FormField,
    HiddenField,
    RadioField,
    SelectMultipleField,
    StringField,
    TextAreaField,
)
from wtforms.validators import InputRequired
from wtforms.widgets import CheckboxInput, ListWidget

from . import model
from .choices import (
    LEGAL_CHOICES,
    PERSON_CHOICES,
    PWD_CHOICES,
    TWO_FACTOR_CHOICES,
    YES_NO_CHOICES,
    YES_NO_UNSURE_CHOICES,
)


class CheckboxesField(SelectMultipleField):
    """Several answers, shown as checkboxes."""

    widget = ListWidget(prefix_label=False)
    option_widget = CheckboxInput()

    def pre_validate(self, form):
        # An answer the form no longer offers is dropped, not an error.
        values = {c[0] for c in self.choices}
        self.data = [d for d in (self.data or []) if d in values]


def _yes_no_unsure(cls, name):
    return RadioField(cls.questions[name], choices=YES_NO_UNSURE_CHOICES, default="")


def _yes_no(cls, name):
    return RadioField(cls.questions[name], choices=YES_NO_CHOICES, default="")


def _text(cls, name):
    return TextAreaField(cls.questions[name])


class NotesForm(Form):
    client_notes = TextAreaField("What the client said")
    consultant_notes = TextAreaField("Consultant notes (not in the take-home copy)")


# --- questionnaire ---------------------------------------------------------------


class TAQDevicesForm(Form):
    title = "Devices"
    live_together = _yes_no(model.TAQDevices, "live_together")
    purchase_device = _yes_no_unsure(model.TAQDevices, "purchase_device")
    purchase_device_which = _text(model.TAQDevices, "purchase_device_which")
    physical_access = _yes_no_unsure(model.TAQDevices, "physical_access")
    physical_access_which = _text(model.TAQDevices, "physical_access_which")
    device_pin = _yes_no_unsure(model.TAQDevices, "device_pin")


class TAQAccountsForm(Form):
    title = "Accounts and passwords"
    pwd_mgmt = CheckboxesField(
        model.TAQAccounts.questions["pwd_mgmt"], choices=PWD_CHOICES
    )
    pwd_mgmt_describe = _text(model.TAQAccounts, "pwd_mgmt_describe")
    pwd_comp = _yes_no_unsure(model.TAQAccounts, "pwd_comp")
    pwd_comp_which = _text(model.TAQAccounts, "pwd_comp_which")


class TAQSharingForm(Form):
    title = "Sharing"
    share_phone_plan = _yes_no(model.TAQSharing, "share_phone_plan")
    phone_plan_admin = CheckboxesField(
        model.TAQSharing.questions["phone_plan_admin"], choices=PERSON_CHOICES
    )
    share_accounts = _yes_no_unsure(model.TAQSharing, "share_accounts")
    share_which = _text(model.TAQSharing, "share_which")


class TAQSmarthomeForm(Form):
    title = "Smart home devices"
    smart_home = _yes_no(model.TAQSmarthome, "smart_home")
    smart_home_setup = CheckboxesField(
        model.TAQSmarthome.questions["smart_home_setup"], choices=PERSON_CHOICES
    )
    smart_home_access = _yes_no_unsure(model.TAQSmarthome, "smart_home_access")
    smart_home_acct_sharing = _yes_no_unsure(
        model.TAQSmarthome, "smart_home_acct_sharing"
    )
    smart_home_acct_linking = _yes_no_unsure(
        model.TAQSmarthome, "smart_home_acct_linking"
    )


class TAQKidsForm(Form):
    title = "Children's devices"
    custody = _yes_no(model.TAQKids, "custody")
    child_phys_access = _yes_no_unsure(model.TAQKids, "child_phys_access")
    child_phone_plan = _yes_no(model.TAQKids, "child_phone_plan")


class TAQLegalForm(Form):
    title = "Legal proceedings"
    legal = CheckboxesField(model.TAQLegal.questions["legal"], choices=LEGAL_CHOICES)


class TAQForm(Form):
    devices = FormField(TAQDevicesForm)
    accounts = FormField(TAQAccountsForm)
    sharing = FormField(TAQSharingForm)
    smarthome = FormField(TAQSmarthomeForm)
    kids = FormField(TAQKidsForm)
    legal = FormField(TAQLegalForm)
    marked_done = BooleanField("The questionnaire is complete")


# --- accounts ---------------------------------------------------------------------


class SuspiciousLoginsForm(Form):
    title = "Devices and logins"
    recognize = _yes_no_unsure(model.SuspiciousLogins, "recognize")
    describe_logins = _text(model.SuspiciousLogins, "describe_logins")
    activity_log = _yes_no_unsure(model.SuspiciousLogins, "activity_log")
    describe_activity = _text(model.SuspiciousLogins, "describe_activity")


class PasswordForm(Form):
    title = "Password"
    last_updated = _text(model.PasswordCheck, "last_updated")
    know = _yes_no_unsure(model.PasswordCheck, "know")
    guess = _yes_no_unsure(model.PasswordCheck, "guess")
    federated = _yes_no_unsure(model.PasswordCheck, "federated")
    federated_which = _text(model.PasswordCheck, "federated_which")
    federated_comp = _yes_no_unsure(model.PasswordCheck, "federated_comp")


class RecoveryForm(Form):
    title = "Recovery settings"
    phone_present = _yes_no(model.RecoverySettings, "phone_present")
    phone = _text(model.RecoverySettings, "phone")
    phone_access = _yes_no_unsure(model.RecoverySettings, "phone_access")
    email_present = _yes_no(model.RecoverySettings, "email_present")
    email = _text(model.RecoverySettings, "email")
    email_access = _yes_no_unsure(model.RecoverySettings, "email_access")


class TwoFactorForm(Form):
    title = "Two-factor authentication"
    enabled = _yes_no(model.TwoFactorSettings, "enabled")
    second_factor_type = CheckboxesField(
        model.TwoFactorSettings.questions["second_factor_type"],
        choices=TWO_FACTOR_CHOICES,
    )
    describe = _text(model.TwoFactorSettings, "describe")
    second_factor_access = _yes_no_unsure(
        model.TwoFactorSettings, "second_factor_access"
    )


class SecurityQForm(Form):
    title = "Security questions"
    present = _yes_no(model.SecurityQuestions, "present")
    know = _yes_no_unsure(model.SecurityQuestions, "know")
    which = _text(model.SecurityQuestions, "which")


class AccountForm(Form):
    platform = StringField(
        "Service (for example Google, iCloud)", validators=[InputRequired()]
    )
    username = StringField("Username or email address", validators=[InputRequired()])
    suspicious_logins = FormField(SuspiciousLoginsForm)
    password_check = FormField(PasswordForm)
    recovery_settings = FormField(RecoveryForm)
    two_factor_settings = FormField(TwoFactorForm)
    security_questions = FormField(SecurityQForm)
    notes = FormField(NotesForm)


# --- devices and apps ---------------------------------------------------------------


class InstallForm(Form):
    knew_installed = _yes_no_unsure(model.InstallInfo, "knew_installed")
    installed = _yes_no_unsure(model.InstallInfo, "installed")
    coerced = _yes_no_unsure(model.InstallInfo, "coerced")


class PermissionForm(Form):
    access = _yes_no_unsure(model.PermissionInfo, "access")
    describe = _text(model.PermissionInfo, "describe")


class AppQuestionsForm(Form):
    appId = HiddenField()
    title = HiddenField()
    install_info = FormField(InstallForm)
    permission_info = FormField(PermissionForm)
    notes = FormField(NotesForm)


class AppQuestionsPageForm(Form):
    apps = FieldList(FormField(AppQuestionsForm))


class ManualAppForm(Form):
    title = StringField("App name")
    spyware = BooleanField("Looks like a spyware app")
    dualuse = BooleanField("Looks like a dual-use app")


class ManualDeviceForm(Form):
    device_nickname = StringField("Device nickname", validators=[InputRequired()])
    device_type = RadioField(
        "Device type",
        choices=[("android", "Android"), ("ios", "iOS"), ("other", "Other")],
        default="other",
    )
    device_manufacturer = StringField("Manufacturer")
    device_model = StringField("Model")
    device_version = StringField("Operating system version")
    is_rooted = RadioField(
        "Does the device look rooted or jailbroken?",
        choices=YES_NO_UNSURE_CHOICES,
        default="",
    )
    rooted_reasons = TextAreaField("Why (if it does)")
    apps = FieldList(FormField(ManualAppForm), min_entries=1)
