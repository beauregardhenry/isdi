"""Accounts for the web interface: `isdi user ...`."""

import click

from isdi.cli.common import _data, _operator_option, cli


def _add_user_interactively(username=None, name=None, role="staff"):
    from isdi import users

    while True:
        username = username or click.prompt("Username (for example jdoe)")
        try:
            username = users.check_username(username)
            if users.by_username(username):
                raise users.AccountError(f"There is already an account {username!r}.")
            break
        except users.AccountError as e:
            click.echo(str(e))
            username = None
    while not (name or "").strip():
        name = click.prompt("Full name")
    password = _new_password()
    user = users.create(username, name, password, role=role)
    click.echo(
        f"✓ Created {user['role']} account {user['username']} for {user['name']}"
    )
    return user


def _new_password():
    from isdi import users

    while True:
        password = click.prompt(
            "Password (at least 12 characters)",
            hide_input=True,
            confirmation_prompt=True,
        )
        try:
            users.check_password(password)
            return password
        except users.AccountError as e:
            click.echo(str(e))


@cli.group("user")
def user_group():
    """Accounts for the web interface (each person signs in with their own)."""


@user_group.command("add")
@click.argument("username", required=False)
@click.option("--name", help="The person's full name (asked for if not given).")
@click.option(
    "--supervisor",
    is_flag=True,
    help="Can open every client. Without it, a staff account opens only the "
    "clients it started.",
)
@_operator_option
def user_add(username, name, supervisor, operator):
    """Create an account. The password is asked for."""
    from isdi import users
    from isdi.config import get_config

    with _data(get_config(), operator):
        try:
            _add_user_interactively(
                username, name, role=users.SUPERVISOR if supervisor else users.STAFF
            )
        except users.AccountError as e:
            raise click.ClickException(str(e))


@user_group.command("list")
@_operator_option
def user_list(operator):
    """List accounts."""
    from isdi import users
    from isdi.config import get_config

    with _data(get_config(), operator):
        rows = users.list_users()
        locked = {r["username"]: users.is_locked(r) for r in rows}
    if not rows:
        click.echo("No accounts yet: isdi user add USERNAME")
    for r in rows:
        state = (
            "disabled"
            if r["disabled"]
            else "locked" if locked[r["username"]] else "active"
        )
        click.echo(
            f"{r['username']:<20} {r['name']:<30} {r['role']:<11} {state:<9} "
            f"last sign-in {r['last_login'] or 'never'}"
        )


def _user_change(username, operator, change):
    from isdi import users
    from isdi.config import get_config

    with _data(get_config(), operator):
        try:
            change(users)
        except users.AccountError as e:
            raise click.ClickException(str(e))


@user_group.command("disable")
@click.argument("username")
@_operator_option
def user_disable(username, operator):
    """Disable an account; its sessions end at their next request."""
    _user_change(username, operator, lambda u: u.set_disabled(username, True))
    click.echo(f"✓ Disabled {username}")


@user_group.command("enable")
@click.argument("username")
@_operator_option
def user_enable(username, operator):
    """Enable a disabled or locked account."""
    _user_change(username, operator, lambda u: u.set_disabled(username, False))
    click.echo(f"✓ Enabled {username}")


@user_group.command("role")
@click.argument("username")
@click.argument("role", type=click.Choice(["staff", "supervisor"]))
@_operator_option
def user_role(username, role, operator):
    """Set an account's role: staff (opens only the clients it started) or
    supervisor (opens every client)."""
    _user_change(username, operator, lambda u: u.set_role(username, role))
    click.echo(f"✓ {username} is now {role}")


@user_group.command("reset-password")
@click.argument("username")
@_operator_option
def user_reset_password(username, operator):
    """Set a new password for an account (and unlock it)."""

    def change(users):
        users.require(username)  # before asking for the password
        users.set_password(username, _new_password())

    _user_change(username, operator, change)
    click.echo(f"✓ New password set for {username}; its other sessions end.")
