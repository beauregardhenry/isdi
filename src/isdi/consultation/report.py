"""The consultation report, made from a client's record.

Two versions:

- the full report, for the clinic's file and for court: the client's name,
  every answer, the risks found, the consultant's notes, and screenshots
  with their SHA-256;
- the take-home copy, for the client: no client name, no consultant
  notes, no names of the clinic or the tool, no screenshot hashes, and a
  neutral title, so a copy found by the person of concern says little.

Both are HTML pages the browser can print or save as PDF. When WeasyPrint
is installed (pip install "isdi-scanner[report]"), ISDi makes the PDF
itself, and the take-home copy can be protected with a password.

Ported from Sherloc's printout, rewritten around consultation/model.py.
"""

import io
import secrets
from datetime import datetime
from typing import Optional

from flask import render_template

from isdi import __version__
from isdi.consultation import model, screenshots, store
from isdi.consultation.choices import answer_text


class PdfUnavailable(RuntimeError):
    """WeasyPrint (or the libraries it needs) is not installed."""


def context(clientid: str, takehome: bool) -> dict:
    docs = store.load_all(clientid)
    record = model.Consultation(
        taq=docs["taq"],
        accounts=docs["accounts"],
        devices=docs["devices"],
        notes=docs["notes"],
    )
    shots = {}
    for target, rows in screenshots.by_target(clientid).items():
        shots[target] = [
            {
                "uri": screenshots.data_uri(clientid, r["id"]),
                "created": r["created"],
                "sha256": r["sha256"],
            }
            for r in rows
        ]
    return {
        "takehome": takehome,
        "client_name": "" if takehome else docs["report_name"],
        "clientid": "" if takehome else clientid,
        "made": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "version": __version__,
        "consultation": record.to_dict(derived=True),
        "risks": {k: [r.to_dict() for r in v] for k, v in record.all_risks().items()},
        "questions": model.Consultation.questions(),
        "answer": answer_text(),
        "shots": shots,
    }


def html(clientid: str, takehome: bool) -> str:
    return render_template("consultation/report.html", **context(clientid, takehome))


def can_make_pdf() -> bool:
    try:
        import pypdf  # noqa: F401
        import weasyprint  # noqa: F401
    except (ImportError, OSError):
        return False
    return True


def neutral_filename() -> str:
    """Says nothing about the client, the clinic or the tool."""
    return f"notes-{secrets.token_hex(4)}.pdf"


def _refuse_fetch(url: str, *args, **kwargs):
    # Images are inline (data: URIs) and styles are in the page: nothing
    # else may be loaded, from disk or the network.
    raise ValueError("the report loads nothing from outside the page")


def _fetcher():
    """A WeasyPrint URL fetcher that refuses everything. data: URIs are
    decoded by WeasyPrint itself."""
    from weasyprint.urls import URLFetcher

    class RefuseAll(URLFetcher):
        def fetch(self, url, headers=None):
            _refuse_fetch(url)

    return RefuseAll()


def pdf(page_html: str, takehome: bool, password: Optional[str] = None) -> bytes:
    """PDF bytes of the report page. Raises PdfUnavailable."""
    try:
        import weasyprint  # noqa: F401
        from weasyprint import HTML
    except (ImportError, OSError) as e:
        raise PdfUnavailable(
            "ISDi cannot make PDFs on this computer: install it with "
            'pip install "isdi-scanner[report]". You can still print the '
            "page or save it as PDF from the browser."
        ) from e
    data = HTML(string=page_html, url_fetcher=_fetcher()).write_pdf()
    if takehome or password:
        data = _neutral(data, password)
    return data


def _neutral(data: bytes, password: Optional[str]) -> bytes:
    """Replace the PDF's metadata (the renderer names itself) and, given a
    password, encrypt it with AES-256."""
    try:
        import pypdf
    except ImportError as e:
        raise PdfUnavailable('Install "isdi-scanner[report]" to protect PDFs.') from e
    writer = pypdf.PdfWriter(clone_from=pypdf.PdfReader(io.BytesIO(data)))
    writer.metadata = {"/Title": "Notes"}
    if password:
        writer.encrypt(password, algorithm="AES-256")
    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()
