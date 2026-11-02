"""Answer choices shared by the consultation forms, the model and the report."""

from wtforms import SelectChoice

SECOND_FACTORS = ["Phone", "Email", "Authenticator App", "Trusted Device", "Other"]
ACCOUNTS = [
    "Google",
    "iCloud",
    "Microsoft",
    "Lyft",
    "Uber",
    "Doordash",
    "Grubhub",
    "Facebook",
    "Twitter",
    "Snapchat",
    "Instagram",
]

EMPTY_CHOICE = [SelectChoice("", "Nothing selected")]
YES_NO_UNSURE_CHOICES = EMPTY_CHOICE + [
    SelectChoice("yes", "Yes"),
    SelectChoice("no", "No"),
    SelectChoice("unsure", "Unsure"),
]
YES_NO_CHOICES = EMPTY_CHOICE + [SelectChoice("yes", "Yes"), SelectChoice("no", "No")]
PERSON_CHOICES = [
    SelectChoice("me", "Me"),
    SelectChoice("poc", "Person of concern"),
    SelectChoice("someoneelse", "Someone else"),
    SelectChoice("unsure", "Unsure"),
]
PWD_CHOICES = [
    SelectChoice("online", "Online notes"),
    SelectChoice("paper", "Paper notes"),
    SelectChoice("pwd_manager", "Password manager"),
    SelectChoice("photo", "Take a photo of it"),
    SelectChoice("other_pwd", "Other"),
    SelectChoice("none", "No specific method"),
]
LEGAL_CHOICES = [
    SelectChoice("ro", "Restraining order"),
    SelectChoice("div", "Divorce or other family court"),
    SelectChoice("cl", "Criminal case"),
    SelectChoice("other_legal", "Other"),
]
DEVICE_TYPE_CHOICES = EMPTY_CHOICE + [
    SelectChoice("android", "Android"),
    SelectChoice("ios", "iOS"),
]
TWO_FACTOR_CHOICES = [
    SelectChoice(x.lower().replace(" ", "_"), x) for x in SECOND_FACTORS
]


def answer_text() -> dict:
    """Saved answer code -> the words shown on the form ("poc" -> "Person of
    concern"), for the report."""
    text = {}
    for choices in (
        YES_NO_UNSURE_CHOICES,
        PERSON_CHOICES,
        PWD_CHOICES,
        LEGAL_CHOICES,
        DEVICE_TYPE_CHOICES,
        TWO_FACTOR_CHOICES,
    ):
        for choice in choices:
            if choice.value:
                text[choice.value] = choice.label
    return text
