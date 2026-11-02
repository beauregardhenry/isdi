import json
import logging
from isdi import audit
from isdi.config import get_config
from isdi.scanner import db
from isdi.web import access, bp
from isdi.web.forms import ClientForm
from flask import render_template, request, session, redirect, url_for

config = get_config()


def _fields(row) -> dict:
    """The consultation notes in a notes row, as plain values."""
    return {c: row.get(c) for c in db.NOTES_FIELDS}


def _values(form) -> dict:
    """The form's values as stored: checkbox lists as JSON strings."""
    return {
        f.name: json.dumps(f.data) if f.type == "SelectMultipleField" else f.data
        for f in form
    }


def _form_from(row) -> ClientForm:
    """The form filled in from a stored notes row."""
    data = _fields(row)
    for field in ClientForm():
        value = data.get(field.name)
        if field.type == "SelectMultipleField" and isinstance(value, str):
            try:
                data[field.name] = json.loads(value)
            except json.JSONDecodeError:
                data[field.name] = []
    return ClientForm(data=data)


@bp.route("/form/", methods=["GET", "POST"])
def client_forms():
    if "clientid" not in session:
        return redirect(url_for("main.index"))
    clientid = session["clientid"]

    if db.get_notes_for_client(clientid):
        return redirect(url_for("main.edit_forms"))

    form = ClientForm(request.form)
    if request.method == "POST" and form.validate():
        values = _values(form)
        try:
            db.create_notes(clientid, values)
        except Exception:
            logging.exception("Could not save the consult form")
            raise
        audit.record("notes_created", clientid=clientid, details=values)
        return render_template(
            "main.html", task="form", formdone="yes", title=config.TITLE
        )

    return render_template(
        "main.html",
        task="form",
        form=form,
        title=config.TITLE,
        clientid=clientid,
    )


@bp.route("/form/edit/", methods=["GET", "POST"])
def edit_forms():
    if request.method == "POST":
        clientnote = request.form.get("clientnote", request.args.get("clientnote"))

        if clientnote:  # if requesting a form to edit
            row = db.get_notes(clientnote)
            if row is None:
                return redirect(url_for("main.edit_forms"))
            if not access.can_open(row["clientid"]):
                access.refused(row["clientid"])
                return "You cannot open this client's notes.", 403
            session["form_edit_pk"] = row["id"]
            return render_template(
                "main.html",
                task="form",
                form=_form_from(row),
                title=config.TITLE,
                clientid=row["clientid"],
            )
        else:  # if edits were submitted
            row = db.get_notes(session.get("form_edit_pk"))
            if row is None:
                return redirect(url_for("main.edit_forms"))
            cid = row["clientid"]
            if not access.can_open(cid):
                access.refused(cid)
                return "You cannot open this client's notes.", 403
            form = ClientForm(request.form)
            if not form.validate():
                # Show the errors; saving now would store invalid values.
                return render_template(
                    "main.html",
                    task="form",
                    form=form,
                    title=config.TITLE,
                    clientid=cid,
                )
            values = _values(form)
            db.update_notes(row["id"], values)
            # The edit replaces the stored values; the audit log keeps the
            # old ones (encrypted), so the history of the notes survives.
            audit.record(
                "notes_edited",
                clientid=cid,
                details={
                    "note_id": row["id"],
                    "changes": audit.changes(_fields(row), values),
                },
            )
            return render_template(
                "main.html", task="form", formdone="yes", title=config.TITLE
            )

    # Staff see only the clients they started; supervisors see all.
    clients = [c for c in db.list_notes() if access.can_open(c["clientid"])]
    return render_template(
        "main.html", clients=clients, task="formedit", title=config.TITLE
    )
