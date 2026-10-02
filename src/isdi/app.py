"""Flask application factory"""

import logging
import secrets
from pathlib import Path
from time import perf_counter
from flask import Flask, g
from flask_wtf.csrf import CSRFProtect

__all__ = ["create_app"]

log = logging.getLogger(__name__)


def create_app(config=None):
    """Create and configure Flask application"""
    from isdi.config import get_config

    if config is None:
        config = get_config()

    # Create Flask app
    app = Flask(
        __name__,
        template_folder=str(Path(__file__).parent / "web" / "templates"),
        static_folder=str(Path(__file__).parent / "web" / "static"),
    )

    # Configuration
    app.config["SECRET_KEY"] = config.FLASK_SECRET
    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{config.database_path}"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    # One token per session; the page is often left open for a whole consult.
    app.config["WTF_CSRF_TIME_LIMIT"] = None

    # Store config in app
    app.config["ISDI_CONFIG"] = config

    # Initialize extensions
    from isdi.web import sa

    db_init_started = perf_counter()
    sa.init_app(app)
    # The server can uninstall apps and drive the connected phone, so any
    # other web page the browser visits must not be able to POST to it.
    CSRFProtect(app)

    def _csp_nonce():
        if "csp_nonce" not in g:
            g.csp_nonce = secrets.token_urlsafe(16)
        return g.csp_nonce

    # Templates mark their own <script> blocks with nonce="{{ csp_nonce() }}".
    app.jinja_env.globals["csp_nonce"] = _csp_nonce

    @app.after_request
    def _security_headers(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        # Pages show text that came from the phone and from the app-info db,
        # so only same-origin files and our own nonce'd blocks may run script.
        # Inline style attributes are still used throughout the templates.
        resp.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; "
            f"script-src 'self' 'nonce-{_csp_nonce()}'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "object-src 'none'; "
            "base-uri 'none'; "
            "form-action 'self'; "
            "frame-ancestors 'none'",
        )
        return resp

    from isdi.scanner.db import init_db

    init_db(app, sa, force=config.TEST)
    log.debug("Database init: %.2fs", perf_counter() - db_init_started)

    # A failure here is a bug; let it stop the server rather than serve a
    # half-working scanner.
    from isdi.web import init_routes

    init_routes(app)

    return app
