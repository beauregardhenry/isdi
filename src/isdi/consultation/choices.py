"""Answer choices shared by the consultation forms, the model and the report."""

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

EMPTY_CHOICE = [("", "Nothing selected")]
YES_NO_UNSURE_CHOICES = EMPTY_CHOICE + [
    ("yes", "Yes"),
    ("no", "No"),
    ("unsure", "Unsure"),
]
YES_NO_CHOICES = EMPTY_CHOICE + [("yes", "Yes"), ("no", "No")]
PERSON_CHOICES = [
    ("me", "Me"),
    ("poc", "Person of concern"),
    ("someoneelse", "Someone else"),
    ("unsure", "Unsure"),
]
PWD_CHOICES = [
    ("online", "Online notes"),
    ("paper", "Paper notes"),
    ("pwd_manager", "Password manager"),
    ("photo", "Take a photo of it"),
    ("other_pwd", "Other"),
    ("none", "No specific method"),
]
LEGAL_CHOICES = [
    ("ro", "Restraining order"),
    ("div", "Divorce or other family court"),
    ("cl", "Criminal case"),
    ("other_legal", "Other"),
]
DEVICE_TYPE_CHOICES = EMPTY_CHOICE + [("android", "Android"), ("ios", "iOS")]
TWO_FACTOR_CHOICES = [(x.lower().replace(" ", "_"), x) for x in SECOND_FACTORS]


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
        for code, words in choices:
            if code:
                text[code] = words
    return text
