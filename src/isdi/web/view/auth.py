"""Signing in and out of the web interface (accounts: isdi/users.py).

Every page needs a signed-in user, except the sign-in page itself and
static files. A session ends:
- when the user signs out (on every browser: a copy of the session
  cookie stops working too);
- after IDLE_MINUTES without a request (automatic logoff);
- when the account is disabled, or its password changed.
"""

import time

from flask import (
    current_app,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from isdi import audit, users
from isdi.config import get_config
from isdi.web import bp

IDLE_MINUTES = 15
OPEN_ENDPOINTS = {"main.login", "static"}


def _idle_seconds() -> int:
    return 60 * int(current_app.config.get("ISDI_IDLE_MINUTES", IDLE_MINUTES))


def _end_session(reason: str) -> None:
    user_id = session.get("user_id")
    if user_id:
        user = users.get(user_id)
        if user:
            if reason == "signed out":
                # Copies of the session cookie stop working too.
                users.sign_out_everywhere(user["id"], time.time())
            with audit.acting_as(users.label(user)):
                audit.record("logout", details={"reason": reason})
    session.clear()


def _signed_in_user():
    """The session's user, or None (ending the session if it expired)."""
    user_id = session.get("user_id")
    if not user_id:
        return None
    user = users.get(user_id)
    if user is None or user["disabled"]:
        _end_session("account disabled")
        return None
    if session.get("token") != users.session_token(user):
        _end_session("password changed")
        return None
    if session.get("signed_in_at", 0) <= (user["signed_out_at"] or 0):
        session.clear()  # signed out since (the logout is already recorded)
        return None
    if time.time() - session.get("last_seen", 0) > _idle_seconds():
        _end_session("idle")
        session["notice"] = "You were signed out after a period of inactivity."
        return None
    return user


@bp.before_app_request
def require_login():
    if request.endpoint in OPEN_ENDPOINTS:
        return None
    user = _signed_in_user()
    if user is None:
        if request.method == "GET" and not request.path.startswith("/scan/status"):
            return redirect(url_for("main.login", next=request.full_path.rstrip("?")))
        return jsonify({"error": "Please sign in again."}), 401
    session["last_seen"] = time.time()
    g.user = user
    g.operator = users.label(user)
    return None


@bp.route("/session/ping", methods=["GET"])
def ping():
    """Called by the page while the user types or clicks: the request
    itself keeps the session from ending as idle."""
    return "", 204


def _safe_next(target):
    """Only paths on this site: never redirect elsewhere after sign-in."""
    if target and target.startswith("/") and not target.startswith("//"):
        return target
    return url_for("main.index")


@bp.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        user, outcome = users.authenticate(
            request.form.get("username", ""), request.form.get("password", "")
        )
        if user:
            target = _safe_next(request.form.get("next"))
            session.clear()  # a new session: nothing carried over
            session["user_id"] = user["id"]
            session["token"] = users.session_token(user)
            session["signed_in_at"] = session["last_seen"] = time.time()
            with audit.acting_as(users.label(user)):
                audit.record("login")
            return redirect(target)
        error = "Wrong username or password, or the account is locked or disabled."
    return (
        render_template(
            "login.html",
            title=get_config().TITLE,
            error=error,
            notice=session.pop("notice", None),
            next=request.values.get("next", ""),
            no_accounts=users.count() == 0,
            max_failed=users.MAX_FAILED,
            lockout_minutes=users.LOCKOUT_MINUTES,
        ),
        401 if error else 200,
    )


@bp.route("/logout", methods=["POST"])
def logout():
    _end_session("signed out")
    return redirect(url_for("main.login"))


@bp.route("/account/password", methods=["GET", "POST"])
def change_password():
    error = message = None
    if request.method == "POST":
        user, _ = users.authenticate(
            g.user["username"], request.form.get("current", "")
        )
        new = request.form.get("new", "")
        if not user:
            error = "The current password is wrong."
        elif new != request.form.get("confirm", ""):
            error = "The new passwords do not match."
        else:
            try:
                users.set_password(user["username"], new)
            except users.AccountError as e:
                error = str(e)
            else:
                # Other sessions of this account end; this one continues.
                session["token"] = users.session_token(users.require(user["username"]))
                message = "Password changed."
    return (
        render_template(
            "password.html",
            title=get_config().TITLE,
            error=error,
            message=message,
        ),
        400 if error else 200,
    )
