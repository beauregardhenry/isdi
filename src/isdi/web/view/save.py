from flask import request, session
from isdi.config import get_config
from isdi.web import bp
from isdi import audit
from isdi.scanner.db import (
    get_app_info_from_db,
    get_clientid_for_scan,
    get_scan_res_from_db,
    get_serial_from_db,
    save_note,
    update_appinfo,
    update_mul_appinfo,
    get_device_from_db,
)
from isdi.web.view.index import get_device
from isdi.scanner.runcmd import is_valid_appid, is_valid_serial

config = get_config()


@bp.route("/saveapps/<int:scanid>", methods=["POST"])
def record_applist(scanid):
    device = get_device_from_db(scanid)
    sc = get_device(device)
    d = request.form
    update_mul_appinfo([(remark, scanid, appid) for appid, remark in d.items()])
    audit.record(
        "app_remarks_saved",
        clientid=get_clientid_for_scan(scanid),
        scanid=scanid,
        details={"remarks": dict(d)},
    )
    return "Success", 200


@bp.route("/savescan/<int:scanid>", methods=["POST"])
def record_scanres(scanid):
    device = get_device_from_db(scanid)
    sc = get_device(device)
    note = request.form.get("notes")
    before = (get_scan_res_from_db(scanid) or {}).get("note")
    r = save_note(scanid, note)
    if note != before:
        audit.record(
            "scan_note_saved",
            clientid=get_clientid_for_scan(scanid),
            scanid=scanid,
            details={"note": [before, note]},
        )
    return is_success(
        r, "Success!", "Could not save the form. See logs in the terminal."
    )


@bp.route("/delete/app/<int:scanid>", methods=["POST"])
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
    r = sc.uninstall(serial=serial, appid=appid)
    if r:
        update_appinfo(scanid=scanid, appid=appid, remark=remark, action=action)
    # Removing an app can destroy evidence: always record the attempt.
    flags = next(
        (a["flags"] for a in get_app_info_from_db(scanid) if a["appid"] == appid), None
    )
    audit.record(
        "app_uninstalled" if r else "app_uninstall_failed",
        clientid=get_clientid_for_scan(scanid),
        scanid=scanid,
        details={"appid": appid, "flags": flags, "remark": remark},
    )
    return is_success(r, "Success!", "Uninstall failed.")


def is_success(b, msg_succ="", msg_err=""):
    if b:
        return msg_succ if msg_succ else "Success!", 200
    else:
        return msg_err if msg_err else "Failed", 401
