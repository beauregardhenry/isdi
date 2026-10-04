"""Web interface modules"""

from flask import Blueprint
from flask_sqlalchemy import SQLAlchemy

# SQLAlchemy instance
sa = SQLAlchemy()

# All pages. The view modules attach their routes to this blueprint when
# they are imported, so every app created by create_app() gets all routes.
bp = Blueprint("main", __name__)


def init_routes(flask_app):
    """Register all routes on flask_app."""
    from isdi.web.view import (  # noqa: F401 (imported for their routes)
        auth,
        consult,
        control,
        details,
        error,
        index,
        instructions,
        privacy,
        save,
        scan,
    )

    flask_app.register_blueprint(bp)


__all__ = ["init_routes", "bp", "sa"]
