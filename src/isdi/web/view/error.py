from isdi.web import bp


@bp.route("/error")
def get_nothing():
    """Route for intentional error."""
    return "foobar"  # intentional non-existent variable
