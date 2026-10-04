import json
import os
import threading
import time
import uuid
from isdi import audit
from isdi.config import get_config
from isdi.web import bp
from isdi.web.access import session_scan
from isdi.web.view.index import get_device
from flask import jsonify, render_template, request, session, redirect, url_for
from markupsafe import escape
from isdi.scanner import db, blocklist
from isdi.scanner.runcmd import is_valid_serial
from isdi.scanner.db import (
    get_client_devices_from_db,
    create_scan,
    create_mult_appinfo,
    first_element_or_none,
)

config = get_config()

_SCAN_JOBS: dict = {}
_SCAN_JOBS_LOCK = threading.Lock()
# Finished jobs hold full scan results in memory; drop them after this long.
_SCAN_JOB_TTL = 60 * 60


def _prune_scan_jobs():
    cutoff = time.time() - _SCAN_JOB_TTL
    with _SCAN_JOBS_LOCK:
        for job_id in [
            k
            for k, j in _SCAN_JOBS.items()
            if j["status"] in ("done", "error") and j["updated_at"] < cutoff
        ]:
            del _SCAN_JOBS[job_id]


def _isrooted_html(rooted, rooted_reason):
    if rooted:
        s = "<strong class='text-danger'>Detected</strong>"
    elif rooted is None:
        s = "Not Detected (some checks incomplete)"
    else:
        s = "Not Detected"
    if rooted_reason:
        if isinstance(rooted_reason, (list, tuple)):
            rooted_reason = "; ".join(str(r) for r in rooted_reason)
        # Reasons include raw device output, so escape before rendering |safe.
        s += f". Reason(s): {escape(str(rooted_reason))}"
    return s


def _create_scan_job(clientid, device, device_owner, serial):
    _prune_scan_jobs()
    job_id = uuid.uuid4().hex
    with _SCAN_JOBS_LOCK:
        _SCAN_JOBS[job_id] = {
            "job_id": job_id,
            "status": "queued",
            "percent": 0,
            "step": "Queued",
            "message": "Preparing scan request",
            "clientid": clientid,
            "device": device,
            "device_owner": device_owner,
            "serial": serial,
            "result": None,
            "error": None,
            "updated_at": time.time(),
        }
    return job_id


def _update_scan_job(job_id, **updates):
    with _SCAN_JOBS_LOCK:
        job = _SCAN_JOBS.get(job_id)
        if not job:
            return None
        job.update(updates)
        job["updated_at"] = time.time()
        return dict(job)


def _get_scan_job(job_id):
    with _SCAN_JOBS_LOCK:
        job = _SCAN_JOBS.get(job_id)
        return dict(job) if job else None


def _job_payload(job):
    if not job:
        return None
    return {
        "job_id": job["job_id"],
        "status": job["status"],
        "percent": job["percent"],
        "step": job["step"],
        "message": job["message"],
        "error": job.get("error"),
        "result_url": url_for("main.scan_result", job_id=job["job_id"]),
    }


def _run_live_scan(
    clientid,
    device,
    device_owner,
    ser,
    job_id=None,
    preserve=False,
    unredacted=False,
):
    """Scan a connected phone and save the result. The raw dump is deleted
    when the scan ends, whatever the outcome: only what the scan keeps
    (encrypted, in the database) remains.

    With preserve, an encrypted evidence copy of the dump is kept; with
    unredacted as well, for Android, it is the adb output as received,
    account email addresses included."""
    sc = get_device(device)
    unredacted = bool(preserve and unredacted and sc and device == "android")
    if unredacted:
        sc.unredacted_serials.add(ser)
    try:
        return _scan_and_save(
            clientid, device, device_owner, ser, job_id, preserve, unredacted
        )
    finally:
        if sc and ser:
            sc.unredacted_serials.discard(ser)
            sc.discard_dump(ser)


def _scan_and_save(
    clientid,
    device,
    device_owner,
    ser,
    job_id=None,
    preserve=False,
    unredacted=False,
):
    def progress(percent, step, message):
        if job_id:
            _update_scan_job(
                job_id,
                status="running",
                percent=percent,
                step=step,
                message=message,
            )

    progress(5, "Starting", "Validating scan request")

    template_d = dict(
        task="home",
        title=config.TITLE,
        platform=config.PLATFORM,
        is_termux=bool(os.environ.get("PREFIX")),
        is_debug=config.DEBUG,
        device=device,
        device_primary_user_sel=device_owner,
        apps={},
        currently_scanned=get_client_devices_from_db(clientid),
        clientid=clientid,
    )

    sc = get_device(device)
    if not sc:
        template_d["error"] = "Please choose one device to scan."
        return template_d, 201

    progress(12, "Connecting", f"Looking for {device} device")
    if not ser:
        template_d["error"] = (
            "A device was not detected. Please reconnect it and try again."
        )
        return template_d, 201
    if not is_valid_serial(ser):
        template_d["error"] = "Invalid device id."
        return template_d, 201

    progress(30, "Reading device", "Collecting device details")
    device_name_print, device_name_map = sc.device_info(serial=ser)

    progress(60, "Scanning apps", "Reading installed apps and classifying them")
    apps = sc.find_spyapps(serialno=ser)

    if len(apps) <= 0:
        template_d["error"] = (
            "The scanning failed. This could be due to many reasons. Try"
            " rerunning the scan from the beginning. If the problem persists,"
            " please report it in the file. <code>report_failed.md</code> in the<code>"
            "phone_scanner/</code> directory. Check the phone manually. Sorry for"
            " the inconvenience."
        )
        return template_d, 201

    progress(82, "Security check", "Checking root or jailbreak status")

    scan_d = {
        "clientid": clientid,
        "serial": config.hmac_serial(ser),
        "device": device,
        "device_model": device_name_map.get("model", "<Unknown>").strip(),
        "device_version": device_name_map.get("version", "<Unknown>").strip(),
        "device_primary_user": device_owner,
    }

    if device == "ios":
        scan_d["device_manufacturer"] = "Apple"
        scan_d["last_full_charge"] = "unknown"
    else:
        scan_d["device_manufacturer"] = device_name_map.get(
            "brand", "<Unknown>"
        ).strip()
        scan_d["last_full_charge"] = device_name_map.get(
            "last_full_charge", "<Unknown>"
        )

    rooted, rooted_reason = sc.isrooted(ser)
    scan_d["is_rooted"] = rooted
    scan_d["rooted_reasons"] = json.dumps(rooted_reason)

    progress(94, "Saving", "Writing scan results to the local database")
    scan_d["operator"] = audit.operator()
    scanid = create_scan(scan_d)

    create_mult_appinfo(
        [
            (scanid, appid, json.dumps(info["flags"]), "", "<new>")
            for appid, info in apps.items()
        ],
        details=sc.dump_details(apps),
    )
    template_d["app_rows"] = db.app_row_ids(scanid)
    audit.record(
        "scan_saved",
        clientid=clientid,
        scanid=scanid,
        details={
            "device": device,
            "serial_hmac": scan_d["serial"],
            "model": scan_d["device_model"],
            "version": scan_d["device_version"],
            "manufacturer": scan_d["device_manufacturer"],
            "nickname": device_owner,
            "rooted": rooted,
            "rooted_reasons": rooted_reason,
            "apps": len(apps),
            "flagged": {a: i["flags"] for a, i in apps.items() if i["flags"]},
            "isdi_version": config.VERSION,
            "blocklist_sha256": blocklist.BLOCKLIST_SHA256,
        },
    )
    if preserve:
        from isdi import evidence

        progress(97, "Saving", "Keeping an encrypted evidence copy")
        template_d["evidence_sha256"] = evidence.preserve(
            sc, ser, scanid, clientid, unredacted=unredacted
        )

    apps_sorted = sorted(
        apps.items(),
        key=lambda item: (-item[1].get("score", 0.0), item[0]),
    )

    isrooted_str = _isrooted_html(rooted, rooted_reason)

    template_d.update(
        dict(
            isrooted=isrooted_str,
            device_name=device_name_print,
            apps=apps,
            apps_sorted=apps_sorted,
            scanid=scanid,
            sysapps=set(),
            serial=ser,
            currently_scanned=get_client_devices_from_db(clientid),
        )
    )

    progress(100, "Complete", "Scan finished")
    return template_d, 200


def _scan_worker(
    job_id,
    clientid,
    device,
    device_owner,
    ser,
    preserve=False,
    unredacted=False,
    operator=None,
):
    # A thread of its own: record what it does under the user who started it.
    with audit.acting_as(operator):
        _scan_job(job_id, clientid, device, device_owner, ser, preserve, unredacted)


def _scan_job(job_id, clientid, device, device_owner, ser, preserve, unredacted):
    try:
        template_d, status_code = _run_live_scan(
            clientid,
            device,
            device_owner,
            ser,
            job_id=job_id,
            preserve=preserve,
            unredacted=unredacted,
        )
        if status_code == 200:
            _update_scan_job(
                job_id,
                status="done",
                percent=100,
                step="Complete",
                message="Scan finished",
                result=template_d,
            )
        else:
            _update_scan_job(
                job_id,
                status="error",
                percent=100,
                step="Failed",
                message=template_d.get("error", "Scan failed"),
                error=template_d.get("error", "Scan failed"),
            )
    except Exception as exc:
        _update_scan_job(
            job_id,
            status="error",
            percent=100,
            step="Failed",
            message=str(exc),
            error=str(exc),
        )


def get_param(key):
    return request.form.get(key, request.args.get(key))


@bp.route("/scan/start", methods=["POST"])
def scan_start():
    if "clientid" not in session:
        return jsonify({"error": "Please start from the home page again."}), 401

    device = get_param("device")
    device_owner = get_param("device_owner")
    if not device:
        return jsonify({"error": "Please choose one device to scan."}), 400
    if not device_owner:
        return jsonify({"error": "Please give the device a nickname."}), 400

    sc = get_device(device)
    if not sc:
        return jsonify({"error": "Please choose one device to scan."}), 400

    ser = get_param("devid")
    if not ser:
        ser = first_element_or_none(sc.devices())

    if not ser:
        return (
            jsonify(
                {
                    "error": (
                        "A device wasn't detected. Please follow the setup instructions and try again."
                    )
                }
            ),
            409,
        )
    if not is_valid_serial(ser):
        return jsonify({"error": "Invalid device id."}), 400

    job_id = _create_scan_job(session["clientid"], device, device_owner, ser)
    worker = threading.Thread(
        target=_scan_worker,
        args=(
            job_id,
            session["clientid"],
            device,
            device_owner,
            ser,
            get_param("preserve_evidence") == "1",
            get_param("evidence_unredacted") == "1",
            audit.operator(),
        ),
        daemon=True,
    )
    worker.start()

    return jsonify(
        {
            "job_id": job_id,
            "status_url": url_for("main.scan_status", job_id=job_id),
            "result_url": url_for("main.scan_result", job_id=job_id),
        }
    )


@bp.route("/scan/status/<job_id>", methods=["GET"])
def scan_status(job_id):
    job = _get_scan_job(job_id)
    if not job:
        return jsonify({"error": "Unknown scan job."}), 404
    return jsonify(_job_payload(job))


@bp.route("/scan/result/<job_id>", methods=["GET"])
def scan_result(job_id):
    job = _get_scan_job(job_id)
    if not job or job["clientid"] != session.get("clientid"):
        return redirect(url_for("main.index"))

    if job.get("status") != "done" or not job.get("result"):
        return jsonify({"error": job.get("error") or "Scan is still running."}), 202

    template_d = dict(job["result"])
    template_d["currently_scanned"] = get_client_devices_from_db(session["clientid"])
    return render_template("main.html", **template_d), 200


@bp.route("/scan", methods=["POST", "GET"])
def scan():
    """Scan a phone without JavaScript (the page normally uses /scan/start).

    Form fields: device ("android", "ios" or "test"), device_owner (the
    nickname), devid (the serial; the first connected phone if empty), and
    the evidence-copy choices."""
    if "clientid" not in session:
        return redirect(url_for("main.index"))

    clientid = session["clientid"]
    device = get_param("device")
    device_owner = get_param("device_owner")
    ser = get_param("devid")

    currently_scanned = get_client_devices_from_db(session["clientid"])
    template_d = dict(
        task="home",
        title=config.TITLE,
        platform=config.PLATFORM,
        is_termux=bool(os.environ.get("PREFIX")),
        is_debug=config.DEBUG,
        device=device,
        # Shown again in the nickname field.
        device_primary_user_sel=device_owner,
        apps={},
        currently_scanned=currently_scanned,
        clientid=session["clientid"],
    )
    sc = get_device(device)
    if not sc:
        template_d["error"] = "Please choose one device to scan."
        return render_template("main.html", **template_d), 201
    if not device_owner:
        template_d["error"] = "Please give the device a nickname."
        return render_template("main.html", **template_d), 201

    if not ser:
        ser = first_element_or_none(sc.devices())

    if not ser:
        error = (
            "<b>A device wasn't detected. Please follow the "
            "<a href='/instruction' target='_blank' rel='noopener'>"
            "setup instructions here.</a></b>"
        )
        template_d["error"] = error
        return render_template("main.html", **template_d), 201

    result_d, status_code = _run_live_scan(
        clientid,
        device,
        device_owner,
        ser,
        preserve=get_param("preserve_evidence") == "1",
        unredacted=get_param("evidence_unredacted") == "1",
    )
    result_d["device_primary_user_sel"] = device_owner
    return render_template("main.html", **result_d), status_code


@bp.route("/scan/saved/<int:scanid>", methods=["GET"])
def saved_scan(scanid):
    """A saved scan, read from the database. The URL carries only the scan
    id: serials, nicknames and app ids in URLs end up in browser history."""
    if "clientid" not in session:
        return redirect(url_for("main.index"))
    # Scan ids are sequential: without this check, any id could be opened.
    scan_res = session_scan(scanid)
    if not scan_res:
        return "Unknown scan", 404
    device = scan_res.get("device")
    sc = get_device(device)

    manufacturer = scan_res.get("device_manufacturer") or ""
    model = scan_res.get("device_model") or ""
    device_name_print = f"{manufacturer} {model}".strip() or "<Unknown device>"

    app_rows = db.get_app_info_from_db(scanid)
    apps = {}
    # Pre-fetch titles from the app-info cache database for this device type
    _title_cache = {}
    if sc and device == "android" and sc.app_info_conn:
        try:
            appids_in_scan = [r["appid"] for r in app_rows if r.get("appid")]
            if appids_in_scan:
                cur = sc.app_info_conn.cursor()
                placeholders = ",".join("?" * len(appids_in_scan))
                cur.execute(
                    f"SELECT appid, title FROM apps WHERE appid IN ({placeholders})",
                    appids_in_scan,
                )
                for r in cur.fetchall():
                    if isinstance(r, dict):
                        _title_cache[r["appid"]] = r.get("title") or ""
                    else:
                        _title_cache[r[0]] = r[1] or ""
        except Exception:
            pass
    for row in app_rows:
        appid = row["appid"]
        try:
            flags = json.loads(row["flags"]) if row["flags"] else []
        except (json.JSONDecodeError, TypeError):
            flags = []
        title = _title_cache.get(appid, "")
        title = title.encode("ascii", errors="ignore").decode("ascii")
        apps[appid] = {
            "title": title,
            "flags": flags,
            "score": blocklist.score(flags),
            "class_": blocklist.assign_class(flags),
            "html_flags": blocklist.flag_str(flags),
        }

    rooted = scan_res.get("is_rooted")
    try:
        rooted_reason = json.loads(scan_res.get("rooted_reasons") or "[]")
    except (json.JSONDecodeError, TypeError):
        rooted_reason = []

    apps_sorted = sorted(
        apps.items(),
        key=lambda item: (-item[1].get("score", 0.0), item[0]),
    )
    template_d = dict(
        task="home",
        title=config.TITLE,
        platform=config.PLATFORM,
        is_termux=bool(os.environ.get("PREFIX")),
        is_debug=config.DEBUG,
        device=device,
        device_primary_user_sel=scan_res.get("device_primary_user"),
        clientid=session["clientid"],
        isrooted=_isrooted_html(rooted, rooted_reason),
        device_name=device_name_print,
        apps=apps,
        apps_sorted=apps_sorted,
        app_rows={r["appid"]: r["id"] for r in app_rows},
        scanid=scanid,
        sysapps=set(),
        serial=scan_res.get("serial"),
        from_dump=True,
        currently_scanned=get_client_devices_from_db(session["clientid"]),
    )
    return render_template("main.html", **template_d), 200
