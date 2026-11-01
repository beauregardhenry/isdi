#!/usr/bin/env python3
"""How well ISDi's matching does against public data, for each release.

- The lists ISDi ships: every listed stalkerware package must be flagged
  and every listed signing certificate matched. A miss is a regression
  and fails the release.
- Real samples: samples.csv from the AssoEchap stalkerware-indicators
  project lists analysed stalkerware APKs with their package name and
  signing certificate. The same project writes the list ISDi uses, so
  this measures ISDi's matching against the samples behind that list,
  not detection of unknown stalkerware.
- Store apps: ISDi's app catalog (app-info.db, from the original ISDi
  research crawl) holds Play Store and App Store apps. It shows how many
  ordinary apps get flagged, by which rule. Some crawled apps carry the
  crawl's own "relevant" label; the name pattern's hits on apps labelled
  "n" are reported as such, not as a measured false-positive rate.

This uses ISDi's own matching code (scanner/blocklist.py), not a copy.
It does not test reading a phone: see `isdi field-test`.

Usage:
  python scripts/scorecard.py --samples samples.csv --app-info app-info.db \\
      [--markdown out.md] [--json out.json]
Exit status 1 when a listed package or certificate is not matched.
"""

import argparse
import csv
import json
import sqlite3
import sys
from collections import Counter
from typing import Any, Dict, List, Optional

from isdi.scanner import blocklist

# Flags that mean "known to be built for monitoring", as the consultation
# and the client summary count them.
KNOWN = {"spyware", "stalkerware", "onstore-spyware", "offstore-spyware"}


def _flags(appids_titles) -> Dict[str, List[str]]:
    apps = [{"appId": a, "title": t or ""} for a, t in appids_titles]
    return {r["appId"]: r["flags"] for r in blocklist.app_title_and_flag(apps)}


def shipped_lists() -> Dict[str, int]:
    listed = [r["appId"] for r in blocklist.APP_FLAGS if r["flag"] == "stalkerware"]
    flags = _flags((a, "") for a in listed)
    signers = blocklist.STALKERWARE_SIGNERS
    return {
        "packages": len(listed),
        "packages_flagged": sum("stalkerware" in flags.get(a, []) for a in listed),
        "signers": len(signers),
        "signers_matched": sum(bool(blocklist.signer_apps({s})) for s in signers),
    }


def samples(path) -> Dict[str, Any]:
    with open(path, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    ids = [
        (r["Package Name"].strip(), r["Certificate"].strip().upper())
        for r in rows
        if r["Package Name"].strip() or r["Certificate"].strip()
    ]
    flags = _flags({(p, "") for p, _ in ids if p})
    by_pkg = by_sig = either = sig_only = pattern_only = 0
    missed: Counter = Counter()
    for pkg, cert in ids:
        f = set(flags.get(pkg, [])) if pkg else set()
        p = bool(f & KNOWN)
        s = bool(cert and blocklist.signer_apps({cert}))
        by_pkg += p
        by_sig += s
        either += p or s
        sig_only += s and not p
        if not (p or s):
            if "regex-spy" in f:
                pattern_only += 1
            else:
                missed[pkg or cert] += 1
    return {
        "total": len(rows),
        "with_identifiers": len(ids),
        "by_package": by_pkg,
        "by_signer": by_sig,
        "by_either": either,
        "signer_only": sig_only,
        "name_pattern_only": pattern_only,
        "missed": sum(missed.values()),
        "missed_packages": sorted(missed),
    }


def catalog(path) -> Dict[str, Any]:
    con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        rows = con.execute("SELECT appId, title, store, relevant FROM apps").fetchall()
    finally:
        con.close()
    rows = [r for r in rows if r[2] in ("playstore", "appstore")]
    flags = _flags((a, t) for a, t, _, _ in rows)
    apps: Counter = Counter()
    known: Counter = Counter()
    pattern: Counter = Counter()
    labelled_n = flagged_n = 0
    examples: List[str] = []
    for appid, title, store, relevant in rows:
        f = set(flags.get(appid, []))
        apps[store] += 1
        known[store] += bool(f & KNOWN)
        pattern[store] += "regex-spy" in f
        if relevant == "n":
            labelled_n += 1
            if "regex-spy" in f:
                flagged_n += 1
                if len(examples) < 5:
                    examples.append(title or appid)
    nonzero = lambda c: {k: v for k, v in sorted(c.items()) if v}
    return {
        "apps": nonzero(apps),
        "known_monitoring": nonzero(known),
        "name_pattern": nonzero(pattern),
        "name_pattern_on_not_relevant": {"labelled": labelled_n, "flagged": flagged_n},
        "name_pattern_examples": examples,
    }


def report(samples_result, catalog_result) -> Dict[str, Any]:
    return {
        "list": shipped_lists(),
        "samples": samples_result,
        "catalog": catalog_result,
    }


def regressions(r) -> List[str]:
    out = []
    lst = r["list"]
    if lst["packages_flagged"] != lst["packages"]:
        out.append(
            f"{lst['packages'] - lst['packages_flagged']} listed stalkerware "
            "packages are not flagged"
        )
    if lst["signers_matched"] != lst["signers"]:
        out.append(
            f"{lst['signers'] - lst['signers_matched']} listed certificates "
            "are not matched"
        )
    return out


def _pct(n: int, d: int) -> str:
    return f"{100 * n / d:.1f}%" if d else "n/a"


def markdown(r) -> str:
    lst, s, c = r["list"], r["samples"], r["catalog"]
    store = lambda d: ", ".join(
        f"{n:,} {'Play Store' if k == 'playstore' else 'App Store'}"
        for k, n in d.items()
    ) or "none"
    lines = [
        "## Detection scorecard",
        "",
        "How ISDi's matching does against public data. It does not test "
        "reading a phone; `isdi field-test` does that.",
        "",
        "**The lists in this release.** "
        f"{lst['packages_flagged']:,} of {lst['packages']:,} listed stalkerware "
        f"packages are flagged; {lst['signers_matched']:,} of "
        f"{lst['signers']:,} listed signing certificates are matched.",
        "",
        "**Known stalkerware samples** (AssoEchap `samples.csv`; "
        f"{s['with_identifiers']:,} of its {s['total']:,} samples record a "
        "package name or certificate). The same project writes the list, so "
        "this checks matching, not detection of unknown apps.",
        "",
        "| Matched by | Samples | Share |",
        "|---|---:|---:|",
        f"| Package name | {s['by_package']:,} | {_pct(s['by_package'], s['with_identifiers'])} |",
        f"| Signing certificate | {s['by_signer']:,} | {_pct(s['by_signer'], s['with_identifiers'])} |",
        f"| Either | {s['by_either']:,} | {_pct(s['by_either'], s['with_identifiers'])} |",
        f"| Certificate only (renamed packages) | {s['signer_only']:,} | |",
        f"| Name pattern only (weak signal) | {s['name_pattern_only']:,} | |",
        f"| Not matched | {s['missed']:,} | |",
        "",
    ]
    if s["missed_packages"]:
        shown = ", ".join(f"`{p}`" for p in s["missed_packages"][:10])
        more = len(s["missed_packages"]) - 10
        lines += [
            f"Not matched: {shown}" + (f" and {more} more." if more > 0 else "."),
            "",
        ]
    pn = c["name_pattern_on_not_relevant"]
    lines += [
        f"**Store apps** (ISDi's app catalog: {store(c['apps'])} apps).",
        "",
        f"- Flagged as known monitoring: {store(c['known_monitoring'])}. "
        "These are store apps the stalkerware list names.",
        f"- Flagged by the name pattern ('spy', 'track', ...): "
        f"{store(c['name_pattern'])}. The pattern's weight is low (blue row).",
        f"- Of the {pn['labelled']:,} apps the original crawl labelled not "
        f"relevant, the name pattern flags {pn['flagged']:,}"
        + (
            ", for example: " + "; ".join(f'"{e}"' for e in c["name_pattern_examples"]) + "."
            if c["name_pattern_examples"]
            else "."
        ),
        "",
    ]
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--samples", required=True)
    ap.add_argument("--app-info", required=True)
    ap.add_argument("--markdown")
    ap.add_argument("--json")
    args = ap.parse_args(argv)
    r = report(samples(args.samples), catalog(args.app_info))
    md = markdown(r)
    if args.markdown:
        with open(args.markdown, "w", encoding="utf-8") as fh:
            fh.write(md)
    else:
        print(md)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(r, fh, indent=2)
    problems = regressions(r)
    for p in problems:
        print(f"::error::{p}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
