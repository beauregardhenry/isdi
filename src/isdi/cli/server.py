"""Running ISDi: the web server and where its files are."""

import webbrowser
from threading import Timer
from time import perf_counter

import click

from isdi import __version__
from isdi.cli.common import _unlock, cli
from isdi.cli.accounts import _add_user_interactively

ANCHOR_REMINDER_DAYS = 7


def _anchor_reminder(last, now=None):
    """A reminder to anchor the audit log, if the last anchor is old."""
    from datetime import datetime, timezone

    now = now or datetime.now(timezone.utc)
    if last:
        days = (now - datetime.fromisoformat(last["time"])).days
        if days < ANCHOR_REMINDER_DAYS:
            return None
        when = f"{days} days ago"
    else:
        when = "never"
    return (
        f"⚠ The audit log was last anchored {when}. Run `isdi audit anchor -o "
        "FILE` and send the file outside the clinic (see COURT_RECORDS.md)."
    )


BACKUP_REMINDER_DAYS = 7


def _backup_reminder(last, now=None):
    """A reminder to back up, if the last backup is old."""
    from datetime import datetime, timezone

    now = now or datetime.now(timezone.utc)
    if last:
        days = (now - datetime.fromisoformat(last["time"])).days
        if days < BACKUP_REMINDER_DAYS:
            return None
        when = f"{days} days ago"
    else:
        when = "never"
    return (
        f"⚠ The last backup was made {when}. Run `isdi backup -o FILE` and "
        "keep the file away from this computer."
    )


@cli.command()
@click.option(
    "--host",
    default=None,
    help="Loopback address to bind to (default: 127.0.0.1). Other addresses "
    "are refused: ISDi serves plain HTTP and must not be reachable from the "
    "network.",
)
@click.option("--port", type=int, default=None, help="Port to bind to (default: 6200)")
@click.option("--debug/--no-debug", default=False, help="Enable debug mode")
@click.option("--test", "test_mode", is_flag=True, help="Run in test mode")
@click.option("--no-browser", is_flag=True, help="Do not open browser automatically")
def run(host, port, debug, test_mode, no_browser):
    """Run the ISDI web server"""
    from isdi.config import get_config
    from isdi.app import create_app

    startup_started = perf_counter()

    # Determine environment
    if test_mode:
        env = "test"
    elif debug:
        env = "development"
    else:
        env = "production"

    config_started = perf_counter()
    config = get_config(env)
    click.echo(f"⏱ Config init: {perf_counter() - config_started:.2f}s")

    final_host = host or config.host
    final_port = port or config.port
    if not _is_loopback(final_host):
        # Plain HTTP: passwords and client data would cross the network in
        # the clear, and anyone on it could try to sign in.
        raise click.ClickException(
            f"Refusing to listen on {final_host}: ISDi only runs on this "
            "computer (127.0.0.1, ::1 or localhost)."
        )
    browser_host = final_host
    _unlock(config)

    # Create app
    app_started = perf_counter()
    app = create_app(config)
    click.echo(f"⏱ App factory: {perf_counter() - app_started:.2f}s")
    from isdi import audit

    with app.app_context():
        audit.record(
            "session_started", details={"isdi_version": __version__, "env": env}
        )
        _ensure_an_account()
        reminders = [
            _anchor_reminder(audit.last_anchor()),
            _backup_reminder(audit.last_action("backup_made")),
        ]
    for reminder in filter(None, reminders):
        click.secho(reminder, fg="yellow", err=True)

    # Open browser after short delay
    if not no_browser and not debug and not test_mode:

        def open_browser():
            webbrowser.open(f"http://{browser_host}:{final_port}")

        Timer(1.5, open_browser).start()

    click.echo(f"🔍 Starting ISDI on http://{final_host}:{final_port}")
    click.echo(f'📁 Data directory: {config.dirs["data"]}')
    click.echo(f"📊 Database: {config.database_path}")
    click.echo(f"⏱ Total startup prep: {perf_counter() - startup_started:.2f}s")

    if test_mode:
        click.echo("🧪 Running in TEST mode")
    elif debug:
        click.echo("🐛 Running in DEBUG mode")

    # Setup logging
    config.setup_logger()

    # Run the app
    app.run(
        host=final_host,
        port=final_port,
        debug=config.DEBUG,
        use_reloader=config.DEBUG,
        reloader_type=(
            "stat" if config.DEBUG else None
        ),  # Use stat-based reloader for better reliability
        extra_files=None,
    )


def _is_loopback(host: str) -> bool:
    import ipaddress

    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def _ensure_an_account():
    """The web interface needs a signed-in user: create the first account
    if there is none."""
    from isdi import audit, users

    if users.count():
        return
    click.secho("\nEach person using ISDi signs in with an account.", bold=True)
    click.echo("Create the first one now; add others with `isdi user add`.")
    click.echo("It is a supervisor account: it can open every client.")
    with audit.acting_as("isdi run (first account)"):
        _add_user_interactively(role=users.SUPERVISOR)


@cli.command()
def info():
    """Show configuration and directory information"""
    from isdi.config import get_config

    config = get_config()

    click.echo("ISDI Configuration:")
    click.echo(f"  Environment: {config.env}")
    click.echo("\nDirectories:")
    click.echo(f'  Data: {config.dirs["data"]}')
    click.echo(f'  Config: {config.dirs["config"]}')
    click.echo(f'  Cache: {config.dirs["cache"]}')
    click.echo("\nData Locations:")
    click.echo(f"  Database: {config.database_path}")
    click.echo(f"  Dumps: {config.dumps_dir}")
    click.echo(f"  Logs: {config.logs_dir}")
    click.echo("\nPackage Data:")
    click.echo(f"  Location: {config.package_data}")
    click.echo(f"  Blocklist: {config.APP_FLAGS_FILE}")


@cli.command()
def paths():
    """Show all configured paths"""
    from isdi.config import get_config
    import json

    config = get_config()

    paths_dict = {
        "directories": {k: str(v) for k, v in config.dirs.items()},
        "data": {
            "database": str(config.database_path),
            "dumps": str(config.dumps_dir),
            "logs": str(config.logs_dir),
        },
        "package": {
            "data": str(config.package_data),
            "blocklist": str(config.APP_FLAGS_FILE),
        },
        "secrets": {
            "keyfile": str(config.keyfile),
            "flask_secret": str(config.flask_secret_file),
        },
    }

    click.echo(json.dumps(paths_dict, indent=2))
