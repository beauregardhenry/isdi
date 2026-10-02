import json
import logging
from isdi.config import get_config
from isdi.web import bp, sa
from isdi.web.model import Client
from isdi.web.forms import ClientForm
from flask import render_template, request, session, redirect, url_for
from isdi.scanner.db import get_client_devices_from_db, new_client_id

config = get_config()


def _lists_to_json(form):
    """Checkbox lists are stored as JSON strings."""
    for field in form:
        if field.type == "SelectMultipleField":
            field.data = json.dumps(field.data)


@bp.route("/form/", methods=["GET", "POST"])
def client_forms():
    if "clientid" not in session:
        return redirect(url_for("main.index"))

    prev_submitted = Client.query.filter_by(clientid=session["clientid"]).first()
    if prev_submitted:
        return redirect(url_for("main.edit_forms"))

    # retrieve form defaults from db schema
    client = Client()
    form = ClientForm(request.form)

    if request.method == "POST" and form.validate():
        _lists_to_json(form)
        form.populate_obj(client)
        client.clientid = session["clientid"]
        try:
            sa.session.add(client)
            sa.session.commit()
        except Exception:
            logging.exception("Could not save the consult form")
            sa.session.rollback()
            raise
        return render_template(
            "main.html", task="form", formdone="yes", title=config.TITLE
        )

    # clients_list = Client.query.all()
    return render_template(
        "main.html",
        task="form",
        form=form,
        title=config.TITLE,
        clientid=session["clientid"],
    )


@bp.route("/form/edit/", methods=["GET", "POST"])
def edit_forms():
    if request.method == "POST":
        clientnote = request.form.get("clientnote", request.args.get("clientnote"))

        if clientnote:  # if requesting a form to edit
            session["form_edit_pk"] = clientnote  # set session cookie
            form_obj = sa.session.get(Client, clientnote)
            if form_obj is None:
                return redirect(url_for("main.edit_forms"))
            form = ClientForm(obj=form_obj)
            for field in form:
                if field.type == "SelectMultipleField":
                    field.data = json.loads("".join(field.data))
            return render_template(
                "main.html",
                task="form",
                form=form,
                title=config.TITLE,
                clientid=form_obj.clientid,
            )
        else:  # if edits were submitted
            form_obj = sa.session.get(Client, session.get("form_edit_pk"))
            if form_obj is None:
                return redirect(url_for("main.edit_forms"))
            cid = form_obj.clientid  # preserve before populate_obj
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
            _lists_to_json(form)
            form.populate_obj(form_obj)
            form_obj.clientid = cid
            sa.session.commit()
            return render_template(
                "main.html", task="form", formdone="yes", title=config.TITLE
            )

    clients = Client.query.all()
    return render_template(
        "main.html", clients=clients, task="formedit", title=config.TITLE
    )
