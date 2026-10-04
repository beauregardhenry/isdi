"""Client records: export, erase, evidence copies, signed files and the audit log."""

import click

from isdi.cli.common import _data, _operator_option, cli


@cli.command()
@click.argument("clientid")
@click.option(
    "-o",
    "--output",
    type=click.Path(dir_okay=False, writable=True),
    help="Write to this file (created owner-readable only) instead of the screen.",
)
@_operator_option
def export(clientid, output, operator):
    """Export everything stored about a client, decrypted, as JSON.

    For a data access or portability request. The export is not encrypted:
    hand it over securely and delete it afterwards."""
    import json
    import os

    from isdi.config import get_config
    from isdi.scanner import db

    from isdi import audit

    config = get_config()
    with _data(config, operator):
        data = db.export_client(clientid)
        if not data["notes"] and not data["scans"]:
            raise click.ClickException(f"Nothing is stored for client {clientid!r}.")
        audit.record(
            "client_exported", clientid=clientid, details={"to_file": bool(output)}
        )
    text = json.dumps(data, indent=2, default=str)
    if output:
        from isdi import crypto
        from isdi.evidence import sign_file

        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text + "\n")
        sig = sign_file(output, crypto.public_key(config.keyfile))
        click.echo(
            f"✓ Wrote {output} and its signature {sig}. It is not encrypted: "
            "delete it once handed over.",
            err=True,
        )
    else:
        click.echo(text)


@cli.command()
@click.argument("clientid")
@click.confirmation_option(
    prompt="Permanently delete everything stored about this client?"
)
@_operator_option
def erase(clientid, operator):
    """Delete everything stored about a client: notes, scans and apps."""
    from isdi.config import get_config
    from isdi.scanner import db

    from isdi import audit

    config = get_config()
    with _data(config, operator):
        counts = db.erase_client(clientid)
        if not any(counts.values()):
            raise click.ClickException(f"Nothing is stored for client {clientid!r}.")
        # The entry records that, when and by whom, not what was erased.
        audit.record("client_erased", clientid=clientid, details=counts)
    click.echo(
        "✓ Deleted "
        + ", ".join(f"{n} {table}" for table, n in counts.items() if n)
        + " row(s)."
    )


@cli.group("evidence")
def evidence_group():
    """Evidence copies of scans (kept when "Keep an evidence copy" is ticked)."""


@evidence_group.command("list")
@click.argument("clientid", required=False)
@_operator_option
def evidence_list(clientid, operator):
    """List kept evidence copies (all, or one client's)."""
    from isdi import evidence
    from isdi.config import get_config

    with _data(get_config(), operator):
        rows = evidence.list_evidence(clientid)
    if not rows:
        click.echo("No evidence copies are kept.")
    for r in rows:
        click.echo(
            f"scan {r['scanid']}  client {r['clientid']}  kept {r['created']}  "
            f"{r['size']} bytes  sha256 {r['dump_sha256']}"
            + ("  unredacted" if r["unredacted"] else "")
        )


@evidence_group.command("export")
@click.argument("scanid", type=int)
@click.option(
    "-o",
    "--output",
    required=True,
    type=click.Path(file_okay=False),
    help="New directory to write the package to.",
)
@_operator_option
def evidence_export(scanid, output, operator):
    """Write a signed evidence package for one scan to a new directory.

    The package (raw dump if kept, results, audit trail, manifest and
    signature) is not encrypted: hand it over securely."""
    from isdi import crypto, evidence
    from isdi.config import get_config

    config = get_config()
    with _data(config, operator):
        try:
            evidence.export_package(scanid, output, crypto.public_key(config.keyfile))
        except (LookupError, FileExistsError, ValueError) as e:
            raise click.ClickException(str(e))
    fp = crypto.fingerprint(crypto.public_key(config.keyfile))
    click.echo(f"✓ Wrote {output}. Signed by key {fp}")
    click.echo("  It is not encrypted: hand it over securely.")


@cli.command("verify")
@click.argument("path", type=click.Path(exists=True))
def verify_cmd(path):
    """Check a signed export file or evidence package (no passphrase needed).

    Compare the fingerprint shown with the one the clinic published
    (`isdi signing-key` on the clinic's computer)."""
    from isdi import evidence

    try:
        result = evidence.verify(path)
    except (OSError, ValueError, KeyError) as e:
        raise click.ClickException(f"Cannot verify {path}: {e}")
    click.echo(f"Signed by key {result['fingerprint']}")
    if not result["ok"]:
        for problem in result["problems"]:
            click.echo(f"  ✗ {problem}")
        raise click.ClickException("Verification FAILED")
    click.echo("✓ Signature valid and every file matches the manifest")


@cli.group("audit")
def audit_group():
    """The audit log: who did what, and when."""


def _read_anchor(path, public):
    """An anchor file's contents, once its signature is checked against this
    installation's key."""
    import json

    from isdi import crypto, evidence

    try:
        signed = evidence.verify(path)
        anchor = json.loads(open(path, encoding="utf-8").read())
    except (OSError, ValueError, KeyError) as e:
        raise click.ClickException(f"Cannot read anchor {path}: {e}")
    if not signed["ok"]:
        raise click.ClickException(f"Anchor {path} does not match its signature")
    if signed["fingerprint"] != crypto.fingerprint(public):
        raise click.ClickException(
            f"Anchor {path} was signed by another key ({signed['fingerprint']})"
        )
    return anchor


@audit_group.command("verify")
@click.option(
    "--anchor",
    "anchors",
    multiple=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Also check the log against an anchor made earlier (repeatable).",
)
@_operator_option
def audit_verify(anchors, operator):
    """Check that no audit entry was altered, inserted or removed.

    With --anchor, also check that the log still holds the entry the anchor
    recorded, unchanged: a log rebuilt or cut short since then fails."""
    from isdi import audit, crypto
    from isdi.config import get_config

    config = get_config()
    with _data(config, operator):
        result = audit.verify()
        head = audit.head()
        public = crypto.public_key(config.keyfile)
        problems = [
            (path, audit.check_anchor(_read_anchor(path, public))) for path in anchors
        ]
    if not result["ok"]:
        raise click.ClickException(f"Audit log check FAILED: {result['problem']}")
    click.echo(
        f"✓ Audit log intact: {result['entries']} entries"
        + (f" ({result['erased']} with erased details)" if result["erased"] else "")
    )
    if head:
        click.echo(f"  Newest entry: {head['id']}, MAC {head['mac']}")
    for path, problem in problems:
        if problem:
            raise click.ClickException(f"Anchor {path} check FAILED: {problem}")
        click.echo(f"✓ Matches anchor {path}")


@audit_group.command("anchor")
@click.option(
    "-o",
    "--output",
    required=True,
    type=click.Path(dir_okay=False, writable=True),
    help="File to write the anchor to (a signature is written next to it).",
)
@_operator_option
def audit_anchor(output, operator):
    """Write a signed record of the audit log's newest entry.

    Send it somewhere outside the clinic's control, for example by email to
    counsel. It holds no client data. Later, `isdi audit verify --anchor
    FILE` shows whether the log was rewritten or cut short since."""
    import json
    import os

    from isdi import audit, crypto
    from isdi.config import get_config
    from isdi.evidence import sign_file

    config = get_config()
    if os.path.exists(output):
        raise click.ClickException(f"{output} already exists")
    with _data(config, operator):
        anchor = audit.make_anchor()
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(json.dumps(anchor, indent=2) + "\n")
    sig = sign_file(output, crypto.public_key(config.keyfile))
    click.echo(
        f"✓ Wrote {output} and {sig}: entry {anchor['newest_entry']['id']}. "
        "Send both outside the clinic, for example by email to counsel."
    )


@audit_group.command("show")
@click.argument("clientid", required=False)
@_operator_option
def audit_show(clientid, operator):
    """List audit entries (all, or one client's), decrypted, as JSON."""
    import json

    from isdi import audit
    from isdi.config import get_config

    with _data(get_config(), operator):
        rows = audit.entries(clientid)
    click.echo(json.dumps(rows, indent=2, default=str))
