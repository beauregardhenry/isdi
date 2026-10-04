from flask import render_template
from isdi.web import bp
from isdi.web.access import session_scan
from isdi.web.view.index import get_device
from isdi.config import get_config
from isdi.scanner import db
import os

config = get_config()


@bp.route("/scan/<int:scanid>/app/<int:row>", methods=["GET"])
def app_details(scanid, row):
    """One app of a scan. The URL holds only ids: a serial or app id in it
    would be kept in the browser's history. Details come from the database,
    never from the phone."""
    scan_res = session_scan(scanid)
    if not scan_res:
        return "Unknown scan", 404
    appid = next(
        (r["appid"] for r in db.get_app_info_from_db(scanid) if r["id"] == row), None
    )
    sc = get_device(scan_res.get("device"))
    if appid is None or sc is None:
        return "Unknown app", 404
    d, info = sc.app_details(scan_res["serial"], appid, stored=True)
    d["appId"] = appid

    return render_template(
        "main.html",
        task="app",
        title=config.TITLE,
        device_primary_user=config.DEVICE_PRIMARY_USER,
        app=d,
        info=info,
        device=scan_res.get("device"),
        is_termux=bool(os.environ.get("PREFIX")),
        is_debug=config.DEBUG,
    )
