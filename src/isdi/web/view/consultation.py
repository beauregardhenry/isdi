"""The consultation record pages (isdi/consultation).

Everything here belongs to the client of the session (session["clientid"]),
like the scans: there is no client id in the URLs, so a page cannot be
pointed at another client's record. Each save is recorded in the audit log
with what was saved, not the answers themselves.
"""

from flask import flash, redirect, render_template, request, session, url_for

from isdi import audit
from isdi.config import get_config
from isdi.consultation import forms, model, store
from isdi.web import bp

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
