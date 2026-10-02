from flask import request, render_template
from isdi.web import app
from isdi.web.view.index import get_device
from isdi.config import get_config
from isdi.scanner.runcmd import is_valid_appid, is_valid_hmac_serial, is_valid_serial
import os

config = get_config()


@app.route("/details/app/<device>", methods=["GET"])
def app_details(device):
    sc = get_device(device)
    if sc is None:
        return "Unknown device type", 400
    appid = request.args.get("appId")
    ser = request.args.get("serial")
    # Saved scans only know the HMAC of the serial; read their stored dump
    # instead of trying to run adb/pymobiledevice3 with it.
    stored = request.args.get("from_dump") == "1"
    valid_serial = is_valid_hmac_serial(ser) if stored else is_valid_serial(ser)
    if not is_valid_appid(appid) or not valid_serial:
        return "Invalid app id or device serial", 400
    d, info = sc.app_details(ser, appid, stored=stored)
    d["appId"] = appid

    return render_template(
        "main.html",
        task="app",
        title=config.TITLE,
        device_primary_user=config.DEVICE_PRIMARY_USER,
        app=d,
        info=info,
        device=device,
        is_termux=bool(os.environ.get("PREFIX")),
        is_debug=config.DEBUG,
    )
