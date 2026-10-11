"""The consultation record pages (isdi/consultation).

Everything here belongs to the client of the session (session["clientid"]),
like the scans: there is no client id in the URLs, so a page cannot be
pointed at another client's record. Each save is recorded in the audit log
with what was saved, not the answers themselves.
"""

from flask import abort, flash, redirect, render_template, request, session, url_for

from isdi import audit
from isdi.config import get_config
from isdi.consultation import forms, model, store
from isdi.scanner import blocklist, db
from isdi.web import bp
from isdi.web.access import session_scan

config = get_config()


def _clientid():
    return session.get("clientid")


def _page(task, **context):
    return render_template(
        "main.html", task=task, title=config.TITLE, clientid=_clientid(), **context
    )


def _saved(kind, **details):
    audit.record(
        "consultation_saved", clientid=_clientid(), details={"part": kind, **details}
    )


@bp.before_request
def _consultation_needs_a_client():
    if request.endpoint and request.endpoint.startswith("main.consultation"):
        if not _clientid():
            return redirect(url_for("main.index"))
    return None


@bp.route("/consultation", methods=["GET"])
def consultation():
    clientid = _clientid()
    record = model.Consultation(
        taq=store.load(clientid, "taq"),
        accounts=store.load(clientid, "accounts"),
        devices=store.load(clientid, "devices"),
        notes=store.load(clientid, "notes"),
    )
    notes_form = forms.NotesForm(data=record.notes.to_dict())
    return _page("consultation", consultation=record, notes_form=notes_form)


@bp.route("/consultation/notes", methods=["POST"])
def consultation_notes():
    form = forms.NotesForm(request.form)
    store.save(_clientid(), "notes", model.ConsultNotes(**form.data).to_dict())
    _saved("notes")
    flash("Notes saved.", "success")
    return redirect(url_for("main.consultation"))


@bp.route("/consultation/questionnaire", methods=["GET", "POST"])
def consultation_questionnaire():
    clientid = _clientid()
    if request.method == "POST":
        form = forms.TAQForm(request.form)
        if form.validate():
            store.save(clientid, "taq", model.TAQData(**form.data).to_dict())
            _saved("taq")
            flash("Questionnaire saved.", "success")
            return redirect(url_for("main.consultation"))
        flash("Some answers could not be saved; see below.")
    else:
        form = forms.TAQForm(data=store.load(clientid, "taq"))
    return _page("consultation-questionnaire", form=form)


# --- accounts -----------------------------------------------------------------


def _accounts():
    return store.load(_clientid(), "accounts")


def _find(accounts, account_id):
    for i, a in enumerate(accounts):
        if a.get("account_id") == account_id:
            return i
    return None


@bp.route("/consultation/accounts/new", methods=["GET", "POST"])
def consultation_account_new():
    return _account_page(None)


@bp.route("/consultation/accounts/<int:account_id>", methods=["GET", "POST"])
def consultation_account(account_id):
    if _find(_accounts(), account_id) is None:
        abort(404)
    return _account_page(account_id)


def _account_page(account_id):
    accounts = _accounts()
    if request.method == "POST":
        form = forms.AccountForm(request.form)
        if form.validate():
            if account_id is None:
                # Ids are never reused: screenshots are filed under them.
                account_id = (
                    max((a.get("account_id", -1) for a in accounts), default=-1) + 1
                )
            record = model.AccountInvestigation(
                account_id=account_id, **form.data
            ).to_dict()
            i = _find(accounts, account_id)
            if i is None:
                accounts.append(record)
            else:
                accounts[i] = record
            store.save(_clientid(), "accounts", accounts)
            _saved("accounts", account_id=account_id)
            flash("Account check saved.", "success")
            return redirect(url_for("main.consultation"))
        flash("The service and the username are needed.")
    elif account_id is None:
        form = forms.AccountForm()
    else:
        form = forms.AccountForm(data=accounts[_find(accounts, account_id)])
    return _page("consultation-account", form=form, account_id=account_id)


@bp.route("/consultation/accounts/<int:account_id>/delete", methods=["POST"])
def consultation_account_delete(account_id):
    accounts = _accounts()
    i = _find(accounts, account_id)
    if i is None:
        abort(404)
    del accounts[i]
    store.save(_clientid(), "accounts", accounts)
    audit.record(
        "consultation_deleted",
        clientid=_clientid(),
        details={"part": "accounts", "account_id": account_id},
    )
    flash("Account check deleted.", "success")
    return redirect(url_for("main.consultation"))


# --- devices and apps ------------------------------------------------------------


def _devices():
    return store.load(_clientid(), "devices")


def _device_index(devices, key):
    for i, d in enumerate(devices):
        if d.get("key") == key:
            return i
    return None


def _device_or_404(key):
    devices = _devices()
    i = _device_index(devices, key)
    if i is None:
        abort(404)
    return devices, i


def _save_devices(devices, key, action="saved"):
    store.save(_clientid(), "devices", devices)
    if action == "saved":
        _saved("devices", device=key)
    else:
        audit.record(
            "consultation_deleted",
            clientid=_clientid(),
            details={"part": "devices", "device": key},
        )


def _scan_apps(scanid):
    """The apps of one of this client's scans: appid -> title, flags,
    install time and version, from the saved scan."""
    from isdi.web.view.index import get_device
    from isdi.web.view.scan import _saved_apps

    scan = session_scan(scanid)
    if not scan:
        return None, {}
    rows = db.get_app_info_from_db(scanid)
    apps = _saved_apps(get_device(scan.get("device")), scan.get("device"), rows)
    # Without app-info.db, the blocklist's name for a listed app is better
    # than none.
    listed = {
        a["appId"]: a.get("title") or ""
        for a in blocklist.app_title_and_flag([{"appId": x} for x in apps])
    }
    for row in rows:
        details = row.get("details") or {}
        if not isinstance(details, dict):
            details = {}
        app = apps.get(row["appid"])
        if app is None:
            continue
        app["title"] = (
            app["title"] or details.get("title") or listed.get(row["appid"], "")
        )
        app["install_time"] = str(
            details.get("firstInstallTime") or details.get("install_time") or ""
        )
        app["app_version"] = str(
            details.get("versionName") or details.get("App Version") or ""
        )
    return scan, apps


def _choose_by_default(app):
    """Apps the blocklist flags are offered checked, unless they are only
    marked as preinstalled."""
    return bool(set(app["flags"]) - {"system-app"})


@bp.route("/consultation/devices/add", methods=["GET", "POST"])
def consultation_device_add():
    devices = _devices()
    if request.method == "POST":
        try:
            scanid = int(request.form.get("scanid", ""))
        except ValueError:
            abort(400)
        key = f"scan-{scanid}"
        if _device_index(devices, key) is None:
            scan = session_scan(scanid)
            if not scan:
                abort(404)
            devices.append(
                model.DeviceCheck(
                    key=key,
                    scanid=scanid,
                    device_type=scan.get("device") or "",
                    device_nickname=scan.get("device_primary_user") or "",
                    device_model=scan.get("device_model") or "",
                    device_version=scan.get("device_version") or "",
                    device_manufacturer=scan.get("device_manufacturer") or "",
                    is_rooted=bool(scan.get("is_rooted")),
                    rooted_reasons=scan.get("rooted_reasons") or "",
                ).to_dict()
            )
            _save_devices(devices, key)
        return redirect(url_for("main.consultation_device_apps", key=key))
    added = {d.get("scanid") for d in devices}
    scans = [
        s for s in db.get_client_devices_from_db(_clientid()) if s["id"] not in added
    ]
    return _page("consultation-device-add", scans=scans)


@bp.route("/consultation/devices/<key>/apps", methods=["GET", "POST"])
def consultation_device_apps(key):
    devices, i = _device_or_404(key)
    device = devices[i]
    if not device.get("scanid"):
        return redirect(url_for("main.consultation_device_manual", key=key))
    scan, apps = _scan_apps(device["scanid"])
    if scan is None:
        abort(404)
    previous = {a["appId"]: a for a in device.get("selected_apps", [])}
    if request.method == "POST":
        chosen = [a for a in request.form.getlist("app") if a in apps]
        selected = []
        for appid in chosen:
            app = dict(previous.get(appid, {}))
            app.update(
                appId=appid,
                title=apps[appid]["title"],
                flags=apps[appid]["flags"],
                install_time=apps[appid].get("install_time", ""),
                app_version=apps[appid].get("app_version", ""),
                investigate=True,
            )
            selected.append(model.AppInfo(**app).to_dict())
        device["selected_apps"] = selected
        _save_devices(devices, key)
        if not selected:
            flash("No apps chosen for questions.", "success")
            return redirect(url_for("main.consultation"))
        return redirect(url_for("main.consultation_device_questions", key=key))
    checked = (
        set(previous)
        if previous
        else {a for a, v in apps.items() if _choose_by_default(v)}
    )
    ordered = sorted(
        apps.items(),
        key=lambda kv: (-kv[1]["score"], (kv[1]["title"] or kv[0]).lower()),
    )
    return _page(
        "consultation-device-apps", device=device, apps=ordered, checked=checked
    )


@bp.route("/consultation/devices/<key>/questions", methods=["GET", "POST"])
def consultation_device_questions(key):
    devices, i = _device_or_404(key)
    device = devices[i]
    apps = device.get("selected_apps", [])
    if request.method == "POST":
        form = forms.AppQuestionsPageForm(request.form)
        answers = {a["appId"] or a["title"]: a for a in form.data["apps"]}
        updated = []
        for app in apps:
            given = answers.get(app["appId"] or app["title"])
            if given:
                app = dict(app)
                for part in ("install_info", "permission_info", "notes"):
                    app[part] = {**app.get(part, {}), **given[part]}
            updated.append(model.AppInfo(**app).to_dict())
        device["selected_apps"] = updated
        _save_devices(devices, key)
        flash("Answers saved.", "success")
        return redirect(url_for("main.consultation"))
    form = forms.AppQuestionsPageForm(data={"apps": apps})
    return _page("consultation-device-questions", device=device, form=form, apps=apps)


@bp.route("/consultation/devices/manual", methods=["GET", "POST"])
def consultation_device_manual_new():
    return _manual_page(None)


@bp.route("/consultation/devices/<key>/manual", methods=["GET", "POST"])
def consultation_device_manual(key):
    _device_or_404(key)
    return _manual_page(key)


def _manual_page(key):
    devices = _devices()
    if request.method == "POST":
        form = forms.ManualDeviceForm(request.form)
        if "add_app" in request.form:
            form.apps.append_entry()
            return _page("consultation-device-manual", form=form, key=key)
        if form.validate():
            if key is None:
                used = [
                    int(d["key"].split("-", 1)[1])
                    for d in devices
                    if d.get("key", "").startswith("manual-")
                ]
                key = f"manual-{max(used, default=0) + 1}"
            data = form.data
            i = _device_index(devices, key)
            previous = {}
            if i is not None:
                previous = {a["title"]: a for a in devices[i].get("selected_apps", [])}
            apps = []
            for row in data.pop("apps"):
                title = (row["title"] or "").strip()
                if not title:
                    continue
                flags = (["spyware"] if row["spyware"] else []) + (
                    ["dual-use"] if row["dualuse"] else []
                )
                app = dict(
                    previous.get(title, {}), title=title, flags=flags, investigate=True
                )
                apps.append(app)
            record = model.DeviceCheck(
                key=key, manual=True, selected_apps=apps, **data
            ).to_dict()
            if i is None:
                devices.append(record)
            else:
                devices[i] = record
            _save_devices(devices, key)
            if apps:
                return redirect(url_for("main.consultation_device_questions", key=key))
            return redirect(url_for("main.consultation"))
        flash("A nickname for the device is needed.")
    elif key is None:
        form = forms.ManualDeviceForm()
    else:
        devices_, i = _device_or_404(key)
        d = devices_[i]
        form = forms.ManualDeviceForm(
            data={
                **d,
                "is_rooted": d.get("is_rooted") or "",
                "apps": [
                    {
                        "title": a["title"],
                        "spyware": "spyware" in a.get("flags", []),
                        "dualuse": "dual-use" in a.get("flags", []),
                    }
                    for a in d.get("selected_apps", [])
                ]
                or [{}],
            }
        )
    return _page("consultation-device-manual", form=form, key=key)


@bp.route("/consultation/devices/<key>/delete", methods=["POST"])
def consultation_device_delete(key):
    devices, i = _device_or_404(key)
    del devices[i]
    _save_devices(devices, key, action="deleted")
    flash("Device removed from the consultation record.", "success")
    return redirect(url_for("main.consultation"))
