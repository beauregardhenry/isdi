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
        accounts=store.load(clientid, "accounts"),
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
