# ISDi records: a one-page brief for counsel

Written by the people who maintain ISDi, not by lawyers. **It is not legal
advice.** The full note, with rule references and the history of earlier
versions' faults, is [COURT_RECORDS.md](../COURT_RECORDS.md).

**What ISDi is.** A tool clinics use with a survivor of intimate partner
violence to check their phone, over USB, for apps that can be used to
monitor someone ("stalkerware"), for rooting or jailbreaking and, on
iPhones, for supervision and configuration profiles. Installed apps are
compared with public and research blocklists and name patterns.

**What it cannot show.** It is not a forensic image. It does not read
messages, photos or location history, recover deleted data, or say who
installed an app or what it collected. "Nothing flagged" does not prove
the phone is not monitored. Some flags (apps with accessibility or
notification access) are common in ordinary apps and are not a finding of
monitoring by themselves. **Uninstalling an app can destroy evidence and
alert whoever installed it**; ISDi warns before every uninstall.

**What it records** (encrypted on the clinic's computer):

- each scan: time, who was signed in, device model and OS, a pseudonym of
  the serial number, findings, and each app with its flags, plus the ISDi
  version and the blocklist's SHA-256;
- an optional evidence copy of the phone's raw output, hashed (SHA-256) at
  the time of the scan;
- the consultation record: questionnaire answers (including about legal
  proceedings), accounts and devices checked, notes, and screenshots, each
  hashed when kept;
- an audit log of every scan, edit (old and new values), uninstall,
  export and erasure.

**What supports authenticity, and its limits.**

| Feature | Limit |
|---|---|
| Signed-in user on every record | Shows the account, not the person at the keyboard |
| UTC timestamps | From the computer's clock, which ISDi does not check |
| Audit log chained with HMAC-SHA256 | Someone with the passphrase could rebuild it; detectable only against an anchor or export made earlier |
| Signed audit anchors kept outside the clinic | Only as strong as where they are kept (an email to counsel works) |
| Ed25519-signed exports and evidence packages | Only meaningful if the clinic published its key fingerprint beforehand |
| SHA-256 of each screenshot | An uploaded image is only what staff chose to upload |

**What helps, starting now.** Have the clinic send you its signing-key
fingerprint in a dated letter; ask for the signed package soon after a
scan; have audit anchors emailed to you regularly; agree when an
unredacted Android copy is needed (it can contain other people's email
addresses); keep the phone and a written chain of custody. In a criminal
case, a forensic examination may carry more weight than ISDi.

**Questions we need you to answer** (all 14 are in COURT_RECORDS.md):

1. Who authenticates a record: the operator with knowledge, or evidence of
   the process (FRE 901(b)(1), (b)(9); MRE 901)? Is an expert needed
   (702)?
2. Can a package be self-authenticated by certification, as FRE 902(13)
   and (14) allow? **We have not verified whether Mississippi has
   equivalents.**
3. Is machine output hearsay? Can clinic records be records of a regularly
   conducted activity (803(6))?
4. Are staff notes and the client's answers discoverable, and does any
   privilege or confidentiality apply? Should staff limit what they write?
5. When should staff advise against uninstalling, given the client's
   safety? How should unencrypted exports be handed over and stored, and
   for how long?

Check the current text of the rules that apply in your court: either the
federal or the Mississippi rules may have changed since this was written.
