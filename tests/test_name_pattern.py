"""The name pattern ("regex-spy"): words like "spy", "track" and "keylog"
in an app's id or title.

It is a weak signal (weight 0.3), and it flagged many apps that have
nothing to do with watching another person: budget, fitness and baby
trackers, parcel and flight tracking, Santa trackers, and apps that look
for tracking. Those contexts now cancel "track", never "spy" or
"keylog". "cheating" counts only with a partner word.

The examples are titles from ISDi's app catalog (app-info.db) and
package names of real stalkerware samples (AssoEchap samples.csv).
"""

import pytest

from isdi.scanner.blocklist import app_title_and_flag, name_pattern

# Every package in samples.csv the pattern matched before this change.
SAMPLE_PACKAGES = [
    "apk.gpstracker", "apk.keylogger", "apk.stracker", "app.spy24.systemwifi",
    "city.russ.alltrackercorp", "city.russ.alltrackerfamily",
    "city.russ.alltrackerinstaller", "com.android.wifi.tracker", "com.apspy.app",
    "com.as.gpstracker", "com.as.keylogger", "com.as.keylogger2",
    "com.atracker.app", "com.chaoqi.spyapp", "com.cocospy", "com.duiyun.cocospy",
    "com.duiyun.cocospy.v2", "com.duiyun.minspy", "com.duiyun.minspy.v2",
    "com.duiyun.neatspy", "com.duiyun.neatspy.v2", "com.duiyun.spyic",
    "com.duiyun.spyier", "com.duiyun.spyier.v2", "com.duiyun.spyine",
    "com.duiyun.spyzie", "com.duiyun.spyzie.v2", "com.dy.spyzie.v4",
    "com.ispyoo", "com.mit.viptrackpro", "com.my.spy.app", "com.panspy.android",
    "com.sc.cocospy.v2", "com.sc.minspy.v2", "com.sc.neatspy.v2",
    "com.sc.safespy.v2", "com.sc.safespy.v3", "com.sc.spyic.v2",
    "com.sc.spyier.v2", "com.sc.spyine.v2", "com.sc.spyzie.v2",
    "com.shadyspy.monitor", "com.spyzee", "com.tag.viptrack", "com.thewispy",
    "com.topspy", "com.topspy.system", "com.wwtspy", "pl.spyone.agent2",
]  # fmt: skip


@pytest.mark.parametrize("appid", SAMPLE_PACKAGES)
def test_known_stalkerware_packages_still_match(appid):
    assert name_pattern(appid)


@pytest.mark.parametrize(
    "title",
    [
        # Watching another person, or able to.
        "Family Locator - GPS Tracker",
        "Find my Lost Phone - Cell Phone Tracker",
        "Track a Phone",
        "Remote SMS, Call, GPS Tracker",
        "Spy Call Recorder Pro 2018",
        "Mail Spy Pro",  # an exception word next to "spy"
        "Email Keylogger",
        "Catch Your Cheating Spouse! A Step-by-Step How To Spy and Phone Tracker Guide",
        "Cheating Partner Tracker",
        "CATCH A CHEATING LOVER",
        "Kids Tracker: Track your child's phone",
        "Hidden Camera: Best Secret Spy",
        # An unrelated word next to a word about a person.
        "Family GPS Tracker and Chat + Baby Monitor Online",
        "Baby Tracker by SMS & GPS",
        "Baby Tracker: Location",
        "Leapteen Parents-Parental Control&ScreenTime Track",
        "Family Screen Time Tracker - Parental Control App",
        "Where's My Staff- Tracking & Attendance system",
        "Mileage Ace: GPS Tracker & Log",
        "Geo Email Tracker",
    ],
)
def test_monitoring_titles_match(title):
    assert name_pattern("", title)


@pytest.mark.parametrize(
    "title",
    [
        "Family Budget Finance Tracking",
        "PennyOwl Allowance Tracker",
        "Track My Expense",
        "MileBug Mileage Log & Expense Tracker for Taxes",
        "TripLog 2.0 Automatic Mileage Log Tracker for Tax",
        "Runtastic Running Tracker PRO",
        "Runkeeper—GPS Running Tracker",
        "GPS Running Workout Tracking with Calorie Counting",
        "FitYou - Fitness Game and Activity Tracker",
        "Map My Tracks Cycling",
        "Ski Tracks",
        "snoww: ski & snowboard tracker",
        "Migraine Buddy - The Migraine and Headache tracker",
        "Baby Food Tracker",
        "Eat Sleep: Simple Baby Tracking",
        "Carb Counter - Track your Carbs in Style",
        "Malaysia Post Tracker",
        "Flight Dashboard - track your location in-flight!",
        "iTrackMail - Easy Email Tracking and Read Receipts",
        "MailRabbit - Email Tracking",
        "NORAD Where is Santa Tracker",
        "Real Santa Claus tracker for Kids - Xmas 2018",
        "TimeStation - Attendance & Time Tracking",
        "Privilege Points Chore Tracker",
        "ROI Lead Tracker",
        "See Who Is Tracking You",
        "Don't Track Me",
        "track phone radiation",
        "Cheating on Math",
        "Cheating Rock-Paper-Scissors FREE",
        "My Calculator: the Cheating calculator for mentalist",
        "Anti Spy Detector",  # already excluded before
        "Spyware Removal Tool",
    ],
)
def test_unrelated_titles_do_not_match(title):
    assert not name_pattern("", title)


def test_id_and_title_are_judged_together():
    """An exception in the title covers a word in the id, and the other
    way round: com.x.budgettracker / "Budget Tracker" is one app."""
    [app] = app_title_and_flag(
        [{"appId": "com.colpit.isavemoneytracker", "title": "Family Budget"}]
    )
    assert "regex-spy" not in app["flags"]
    [app] = app_title_and_flag(
        [{"appId": "com.example.spy", "title": "Family Budget Tracker"}]
    )
    assert "regex-spy" in app["flags"]


def test_words_inside_an_id_are_not_exceptions():
    """com.solarhk.pushflight is a friend locator, not a flight tracker."""
    assert name_pattern(
        "com.solarhk.pushflight", "Here I Come - Friend Locator, GPS Phone Tracker"
    )


def test_a_disguise_in_the_title_does_not_hide_the_id():
    """Stalkerware poses as antivirus: "anti" in the title must not cancel
    "spy" in the id."""
    for title in ("Antivirus Pro", "Anti Theft", "Removal Tool"):
        [app] = app_title_and_flag([{"appId": "com.spy.agent", "title": title}])
        assert "regex-spy" in app["flags"], title
