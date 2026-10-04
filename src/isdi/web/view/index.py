from isdi.config import get_config
from isdi.web import bp
from flask import g, render_template, request, session
from isdi import users
from isdi.scanner import AndroidScanner, IosScanner, TestScanner
from isdi.scanner.db import get_client_devices_from_db, new_client_id
import os

config = get_config()

# One scanner per kind of phone, shared by all requests. Creating them does
# not touch any phone; the home page lists the connected phones (adb and
# usbmuxd) so the operator can pick one before scanning.
android = AndroidScanner()
ios = IosScanner()
test = TestScanner()


def get_device(k):
    return {"android": android, "ios": ios, "test": test}.get(k)


@bp.route("/", methods=["GET"])
def index():
    # clientid = request.form.get('clientid', request.args.get('clientid'))
    # if not clientid: # if not coming from notes

    newid = request.args.get("newid")
    # if it's a new day (see app.permenant_session_lifetime),
    # or the client devices are all scanned (newid),
    # ask the DB for a new client ID (additional checks in DB).
    if "clientid" not in session or (newid is not None):
        session["clientid"] = new_client_id()
        # The client this account started: a staff account may reopen its
        # notes later (isdi/web/access.py).
        users.grant(g.user["id"], session["clientid"])

    return render_template(
        "main.html",
        title=config.TITLE,
        platform=config.PLATFORM,
        is_termux=bool(os.environ.get("PREFIX")),
        is_debug=config.DEBUG,
        task="home",
        devices={
            "Android": android.devices(),
            "iOS": ios.devices(),
            "Test": test.devices(),
        },
        apps={},
        clientid=session["clientid"],
        currently_scanned=get_client_devices_from_db(session["clientid"]),
    )
