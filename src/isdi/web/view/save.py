from flask import request, session
from isdi.config import get_config
from isdi.web import app
from isdi.scanner.db import (
    get_serial_from_db,
    save_note,
    update_appinfo,
    update_mul_appinfo,
    create_report,
    get_device_from_db,
)
from isdi.web.view.index import get_device
from isdi.scanner.runcmd import is_valid_appid, is_valid_serial

config = get_config()


@app.route("/saveapps/<scanid>", methods=["POST"])
def record_applist(scanid):
    device = get_device_from_db(scanid)
    sc = get_device(device)
    d = request.form
    update_mul_appinfo([(remark, scanid, appid) for appid, remark in d.items()])
    return "Success", 200


@app.route("/savescan/<scanid>", methods=["POST"])
def record_scanres(scanid):
    device = get_device_from_db(scanid)
    sc = get_device(device)
    note = request.form.get("notes")
    r = save_note(scanid, note)
    create_report(session["clientid"])
    # create_report(request.form.get('clientid'))
    return is_success(
        r, "Success!", "Could not save the form. See logs in the terminal."
    )


@app.route("/delete/app/<scanid>", methods=["POST"])
def delete_app(scanid):
    device = get_device_from_db(scanid)
    sc = get_device(device)
    if sc is None:
        return "Unknown scan", 404
    # The DB stores only the HMAC of the serial, so the page sends the raw
    # serial back; it must belong to this scan.
    serial = request.form.get("serial", "")
    appid = request.form.get("appid")
    if not is_valid_serial(serial) or not is_valid_appid(appid):
        return "Invalid app id or device serial", 400
    if config.hmac_serial(serial) != get_serial_from_db(scanid):
        return "Device does not match this scan", 400
    remark = request.form.get("remark")
    action = "delete"
    # TODO: Record the uninstall and note
    r = sc.uninstall(serial=serial, appid=appid)
    if r:
        update_appinfo(scanid=scanid, appid=appid, remark=remark, action=action)
    else:
        print("Uninstall failed. r={}".format(r))
    return is_success(r, "Success!", config.error())


def is_success(b, msg_succ="", msg_err=""):
    if b:
        return msg_succ if msg_succ else "Success!", 200
    else:
        return msg_err if msg_err else "Failed", 401
