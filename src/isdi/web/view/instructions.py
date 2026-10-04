from isdi.config import get_config
from flask import render_template, request, session
from isdi.web import bp
import os

config = get_config()


@bp.route("/instruction", methods=["GET"])
def instruction():
    return render_template(
        "main.html",
        task="instruction",
        title=config.TITLE,
        is_termux=bool(os.environ.get("PREFIX")),
        is_debug=config.DEBUG,
    )
