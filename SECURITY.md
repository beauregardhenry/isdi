# Security policy

ISDi is used to check the phones of people experiencing intimate partner
violence. A bug that hides stalkerware, exposes scan results, or lets
someone act on a connected phone can put a person at risk, so we treat
those as security issues.

## Supported versions

| Version | Supported |
| --- | --- |
| Latest release of this fork ([releases](https://github.com/beauregardhenry/isdi/releases)) | Yes |
| Older releases of this fork | No; upgrade to the latest release |
| `isdi-scanner` on PyPI (upstream, 1.0.9 and earlier) | Not maintained here. 1.0.9 has known, serious vulnerabilities; switch to this fork's latest release |

Install or upgrade with:

```bash
pip install "git+https://github.com/beauregardhenry/isdi@<latest tag>"
```

## Reporting a vulnerability

Please report privately through GitHub:
**[Report a vulnerability](https://github.com/beauregardhenry/isdi/security/advisories/new)**
(the Security tab of this repository).

Do not open a public issue, pull request, or discussion for a
vulnerability.

Include, as far as you can:

- what an attacker can do, and what they need (network access, a web
  page the operator visits, access to the phone, ...);
- the steps to reproduce it, and the ISDi version or commit;
- your operating system and the phone's platform (Android or iOS).

**Never include real people's data.** No scan results, phone dumps,
screenshots, serial numbers, or consultation notes from a real device or
client. Use a test phone or describe the data instead.

You will get a reply in the private advisory thread. Fixes are published
as a new release, and the advisory is made public once a fixed release is
available.

## What counts

In scope:

- the web interface (`isdi run`): injection, cross-site scripting or
  request forgery, unintended network exposure, access to another
  client's data;
- scanning: commands run on the computer or phone, stalkerware or root
  and jailbreak indicators that are missed or can be hidden, wrong
  results shown for a device;
- data handling: client data readable from disk without the passphrase
  (see [DATA_PROTECTION.md](DATA_PROTECTION.md)), raw dumps kept after a
  scan, or scan data, notes, secrets or screenshots stored or logged
  where they should not be.

Out of scope here (please report them upstream instead):

- vulnerabilities in dependencies such as Flask, pymobiledevice3, adb,
  Bootstrap or jQuery, unless ISDi uses them unsafely;
- the upstream project, [stopipv/isdi](https://github.com/stopipv/isdi),
  and its PyPI package.

A stalkerware app that ISDi does not flag can be reported as a normal
[issue](https://github.com/beauregardhenry/isdi/issues), unless the
report itself would reveal something sensitive.
