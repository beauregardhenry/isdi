"""Flask application factory"""

from html import escape
from pathlib import Path
from time import perf_counter
from flask import Flask
from flask_wtf.csrf import CSRFProtect

__all__ = ["create_app"]


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

    @app.after_request
    def _security_headers(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        return resp

    try:
        from isdi.scanner.db import init_db

        init_db(app, sa, force=config.TEST)
    except Exception as e:
        print(f"Warning: Could not initialize database: {e}")
    else:
        print(f"Database init: {perf_counter() - db_init_started:.2f}s")

    # Register routes
    routes_started = perf_counter()
    try:
        from isdi.web import init_routes

        init_routes(app)
    except Exception as e:
        print(f"Warning: Could not register routes: {e}")

        # Create a simple test route
        @app.route("/")
        def index():
            return f"""
            <html>
            <head><title>ISDI</title></head>
            <body>
                <h1>ISDi - Stalkerware Scanner</h1>
                <p>Server is running but web routes are not fully initialized.</p>
                <p>Data directory: {escape(str(config.dirs['data']))}</p>
                <p>Database: {escape(str(config.database_path))}</p>
            </body>
            </html>
            """

    else:
        print(f"Route import/init: {perf_counter() - routes_started:.2f}s")

    return app
