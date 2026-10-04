# If changes are made to this model, please run
# `flask db migrate` and then delete the drops to other tables from the upgrade() method in
# migrations/versions/<version>.py
# before running `flask db upgrade` and re-launching the server.
# if the migrations folder isn't present, run `flask db init` first.
# _order in ClientForm should be modified .

from sqlalchemy.types import Text, TypeDecorator
from wtforms.validators import InputRequired

from isdi import crypto
from isdi.web import sa


class Encrypted(TypeDecorator):
    """A column stored encrypted (AES-256-GCM, see isdi/crypto.py). The
    column name is authenticated with the value, as in isdi/scanner/db.py,
    so both read the same data."""

    impl = Text
    cache_ok = True

    def __init__(self, column: str):
        super().__init__()
        self.column = column

    def process_bind_param(self, value, dialect):
        return crypto.encrypt(self.column, value)

    def process_result_value(self, value, dialect):
        return crypto.decrypt(self.column, value)


class Client(sa.Model):
    __tablename__ = "clients_notes"
    _d = {"default": "", "server_default": ""}  # makes migrations smooth
    _d0 = {"default": "0", "server_default": "0"}
    _lr = lambda label, req: {
        "label": label + "*" if req == "r" else label,
        "validators": InputRequired() if req == "r" else "",
    }
    id = sa.Column(sa.Integer, primary_key=True)
    # In UTC (SQLite's CURRENT_TIMESTAMP), not local time: in US Eastern
    # daylight time it reads 4 hours ahead.
    created_at = sa.Column(sa.DateTime, default=sa.func.current_timestamp())

    # Links the notes to the client's scans (scan_res.clientid) in the same
    # database.
    clientid = sa.Column(sa.String(100), nullable=False, **_d)

    consultant_initials = sa.Column(
        Encrypted("consultant_initials"),
        nullable=False,
        info=_lr("Consultant Names (separate with commas)", "r"),
        **_d,
    )

    fjc = sa.Column(
        Encrypted("fjc"),
        nullable=False,
        info=_lr("FJC", "r"),
        **_d,
    )

    preferred_language = sa.Column(
        Encrypted("preferred_language"),
        nullable=False,
        info=_lr("Preferred language", "r"),
        default="English",
        server_default="English",
    )

    referring_professional = sa.Column(
        Encrypted("referring_professional"),
        nullable=False,
        info=_lr("Name of Referring Professional", "r"),
        **_d,
    )

    referring_professional_email = sa.Column(
        Encrypted("referring_professional_email"),
        nullable=True,
        info={"label": "Email of Referring Professional (Optional)"},
    )

    referring_professional_phone = sa.Column(
        Encrypted("referring_professional_phone"),
        nullable=True,
        info={"label": "Phone number of Referring Professional (Optional)"},
    )

    caseworker_present = sa.Column(
        Encrypted("caseworker_present"),
        nullable=False,
        info=_lr("Caseworker present", "r"),
        **_d,
    )

    caseworker_present_safety_planning = sa.Column(
        Encrypted("caseworker_present_safety_planning"),
        nullable=False,
        info=_lr("Caseworker present for safety planning", "r"),
        **_d,
    )

    caseworker_recorded = sa.Column(
        Encrypted("caseworker_recorded"),
        nullable=False,
        info=_lr("If caseworker present, permission to audio-record them", "r"),
        **_d,
    )

    recorded = sa.Column(
        Encrypted("recorded"),
        nullable=False,
        info=_lr("Permission to audio-record clinic", "r"),
        **_d,
    )

    chief_concerns = sa.Column(
        Encrypted("chief_concerns"),
        nullable=False,
        info=_lr("Chief concerns", "r"),
        **_d,
    )

    chief_concerns_other = sa.Column(
        Encrypted("chief_concerns_other"),
        nullable=False,
        info=_lr("Chief concerns if not listed above (Optional)", ""),
        **_d,
    )

    android_phones = sa.Column(
        Encrypted("android_phones"),
        nullable=False,
        info=_lr("# of Android phones brought in", "r"),
        **_d0,
    )

    android_tablets = sa.Column(
        Encrypted("android_tablets"),
        nullable=False,
        info=_lr("# of Android tablets brought in", "r"),
        **_d0,
    )

    iphone_devices = sa.Column(
        Encrypted("iphone_devices"),
        nullable=False,
        info=_lr("# of iPhones brought in", "r"),
        **_d0,
    )

    ipad_devices = sa.Column(
        Encrypted("ipad_devices"),
        nullable=False,
        info=_lr("# of iPads brought in", "r"),
        **_d0,
    )

    macbook_devices = sa.Column(
        Encrypted("macbook_devices"),
        nullable=False,
        info=_lr("# of MacBooks brought in", "r"),
        **_d0,
    )

    windows_devices = sa.Column(
        Encrypted("windows_devices"),
        nullable=False,
        info=_lr("# of Windows laptops brought in", "r"),
        **_d0,
    )

    echo_devices = sa.Column(
        Encrypted("echo_devices"),
        nullable=False,
        info=_lr("# of Amazon Echoes brought in", "r"),
        **_d0,
    )

    other_devices = sa.Column(
        Encrypted("other_devices"),
        nullable=True,
        info=_lr("Other devices brought in if not listed above (Optional)", ""),
        **_d,
    )

    # consider adding checkboxes for this
    checkups = sa.Column(
        Encrypted("checkups"),
        nullable=True,
        info=_lr("List apps/accounts manually checked (Optional)", ""),
        **_d,
    )

    checkups_other = sa.Column(
        Encrypted("checkups_other"),
        nullable=True,
        info=_lr("Other apps/accounts manually checked (Optional)", ""),
        **_d,
    )

    vulnerabilities = sa.Column(
        Encrypted("vulnerabilities"),
        nullable=False,
        info=_lr("Vulnerabilities discovered", "r"),
        **_d,
    )

    vulnerabilities_trusted_devices = sa.Column(
        Encrypted("vulnerabilities_trusted_devices"),
        nullable=True,
        info=_lr(
            "List accounts with unknown trusted devices if discovered (Optional)", ""
        ),
        **_d,
    )

    vulnerabilities_other = sa.Column(
        Encrypted("vulnerabilities_other"),
        nullable=True,
        info=_lr("Other vulnerabilities discovered (Optional)", ""),
        **_d,
    )

    safety_planning_onsite = sa.Column(
        Encrypted("safety_planning_onsite"),
        nullable=False,
        info=_lr("Safety planning conducted onsite", "r"),
        **_d,
    )

    changes_made_onsite = sa.Column(
        Encrypted("changes_made_onsite"),
        nullable=True,
        info=_lr("Changes made onsite (Optional)", ""),
        **_d,
    )

    unresolved_issues = sa.Column(
        Encrypted("unresolved_issues"),
        nullable=True,
        info=_lr("Unresolved issues (Optional)", ""),
        **_d,
    )

    follow_ups_todo = sa.Column(
        Encrypted("follow_ups_todo"),
        nullable=True,
        info=_lr("Follow-ups To-do (Optional)", ""),
        **_d,
    )

    general_notes = sa.Column(
        Encrypted("general_notes"),
        nullable=True,
        info=_lr("General notes (Optional)", ""),
        **_d,
    )

    case_summary = sa.Column(
        Encrypted("case_summary"),
        nullable=True,
        info=_lr(
            'Case Summary (Can fill out after consult, see "Edit previous forms")', ""
        ),
        **_d,
    )

    # way to edit data/add case summaries afterwards? Or keep text files.

    def __repr__(self):
        return "client seen on {}".format(self.created_at)
