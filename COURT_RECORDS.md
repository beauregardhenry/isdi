# ISDi records in court: a note for counsel

This note is for an attorney deciding whether, and how, records made with
ISDi can be used in a protective-order hearing, a family-court matter or a
criminal case, in Mississippi or elsewhere in the United States. It was
written by the people who maintain this software, not by lawyers. It
describes what the software does and does not do, and lists the questions
we think counsel needs to answer. **It is not legal advice.**

Rule numbers below are to the Federal Rules of Evidence (FRE). The
Mississippi Rules of Evidence (MRE) are largely patterned on the federal
rules, but the wording and the adopted subsections can differ, and either
may have changed since this was written. **Check the current text of the
rules that apply in your court.** Where we are unsure whether Mississippi
has a matching rule, we say so.

## What ISDi is, and is not

ISDi checks a phone for apps that can be used to monitor someone
("stalkerware") and for signs that the phone was rooted or jailbroken. It
was developed by researchers studying technology abuse in intimate partner
violence; its method is described in "Clinical Computer Security for
Victims of Intimate Partner Violence" (USENIX Security 2019), and its
original app list in "The Spyware Used in Intimate Partner Violence" (IEEE
S&P 2018). This version is a maintained fork:
<https://github.com/beauregardhenry/isdi>.

- **What it reads.** The phone, connected by USB, is queried through the
  standard developer interfaces:
  - On Android: `adb`, the system's own `dumpsys` output.
  - On iOS: pymobiledevice3, the app list and device information.
- **What it concludes.** Each installed app is compared with a blocklist,
  which includes the public stalkerware-indicators list maintained by
  Échap, and with name patterns. Matching apps are flagged.
- **What it does not do.**
  - It does not make a forensic image of the phone.
  - It does not recover deleted data or read messages, photos or
    location history.
  - It cannot say who installed an app or what the app collected.
- **What a clean result means.** "Nothing flagged" does not prove the phone
  is not monitored. Monitoring can use apps not on the lists, built-in
  features (family sharing, location sharing) or the person's online
  accounts.
- **It can change the phone.** The privacy checks open settings screens,
  and ISDi can uninstall apps. Uninstalling can destroy evidence, and can
  alert whoever installed the app. ISDi warns before every uninstall.
- **It can change.** Results depend on the ISDi version and the blocklist
  in use. Both are recorded with each scan (the blocklist by its SHA-256),
  so a result can be checked against the same version.

For a criminal case, a forensic examination by a qualified examiner
(often through law enforcement) may carry more weight than ISDi, and
preserving the phone itself may matter more than any ISDi record.

## What records ISDi keeps

All are stored encrypted on the clinic's computer (see
[DATA_PROTECTION.md](DATA_PROTECTION.md)).

| Record | Contents |
|---|---|
| Scan | Time; operator's name; device type, model and OS version; a pseudonym of the serial number (HMAC); root or jailbreak findings; each app with its flags; per app, what the phone reported (install and update times, permissions, data use) |
| Consultation notes | The clinic's intake form |
| Audit log | Every scan, note, edit (old and new values), uninstall attempt, export and erasure, with time (UTC) and operator |
| Evidence copy (optional) | When "Keep an encrypted evidence copy" is ticked: the raw dump of the phone, and its SHA-256 recorded at the time of the scan. For Android, either with email addresses blanked out (the default) or, if "keep it unredacted" is ticked, the output as received |
| Audit anchors | Signed records of the audit log's newest entry, made with `isdi audit anchor` and kept outside the clinic |

Exports:

- `isdi export CLIENTID -o file.json`: everything about a client, with a
  signature file.
- `isdi evidence export SCANID -o DIR`: a package for one scan. It contains:
  - the raw dump (if kept);
  - the results;
  - the scan's audit trail;
  - a manifest with the SHA-256 of each file, signed with the clinic's
    key.

## What supports authenticity, and its limits

| Feature | What it shows | Limit |
|---|---|---|
| Operator name | Who says they ran the scan | Typed by the operator at startup; ISDi has no user accounts or logins |
| Timestamps (UTC) | When the scan or change was recorded | Taken from the computer's clock, which ISDi does not check |
| SHA-256 of the raw dump, recorded at scan time and in the audit log | The kept dump is the one taken during the scan | For Android, the default copy is ISDi's record of the phone's output, with email addresses redacted and whitespace normalised. An unredacted copy is the output as ISDi received it from `adb`, as text. Neither is a forensic image |
| Audit log chained with HMAC-SHA256 | Entries were not altered, inserted or removed (`isdi audit verify`) | Anyone with the passphrase could rebuild the whole log, or remove the newest entries. Both are detectable against an anchor or export made earlier, but only for entries up to the one it recorded |
| Audit anchors (`isdi audit anchor`) | The log held a given entry, unchanged, when the anchor was made (`isdi audit verify --anchor FILE`) | Only as strong as where the anchor is kept: it must be somewhere the clinic cannot change, for example an email to counsel, which records when it arrived. Entries after the anchor are covered only by a later one |
| Ed25519 signature on exports | Files were not changed since export, and were signed by the key with the fingerprint shown (`isdi verify`) | Anyone can sign with a key of their own: the fingerprint must match the one the clinic published beforehand (`isdi signing-key`). The key is only as trustworthy as its custody |
| Encryption at rest | Records were not readable or changeable without the passphrase | People who know the passphrase can change records (the audit log shows changes made through ISDi) |

Practices that make these stronger:

- Publish the clinic's signing-key fingerprint where it can be checked
  later, for example in a dated letter to counsel.
- Export early: give counsel the signed package soon after the scan, so
  later changes would not match it.
- Anchor the audit log regularly (`isdi audit anchor -o FILE`; `isdi run`
  reminds you after 7 days) and send each anchor and its `.sig` file
  outside the clinic, for example by email to counsel. An anchor holds no
  client data: only an entry number, its time and its MAC.
- Decide, with counsel, when an unredacted Android copy is needed. The
  email addresses of accounts on the phone can matter, but they may belong
  to someone other than the client.
- Keep the passphrase to a small, named group, and run ISDi under a
  dedicated computer account.
- Keep the computer's clock synchronised.
- Write down who had the phone and the computer, and when (chain of
  custody). ISDi records only what happens inside ISDi.
- Take photographs or screenshots of what the phone shows. ISDi does not
  record the screen, except screenshots shown during privacy checks, which
  are not saved.

## Questions for counsel

Authentication (FRE 901; MRE 901):

1. Who will testify that a record is what it claims to be? The operator who
   ran the scan, with knowledge (901(b)(1)), may be the simplest.
2. Is evidence about the process needed, showing that ISDi produces an
   accurate result (901(b)(9))? If so, who gives it: clinic staff or an
   expert?

Self-authentication by certification:

3. Can an evidence package be self-authenticated by certification? The
   federal rules allow this for records generated by an electronic process
   (FRE 902(13)) and for data copied from a device, identified by hash
   (FRE 902(14)). Both were added to the federal rules in 2017. **We have
   not verified whether the current Mississippi rules include equivalents;
   please check.**

Hearsay:

4. App lists and flags are machine output; consultation notes and remarks
   are staff statements. Which, if either, is hearsay?
5. Could clinic records qualify as records of a regularly conducted
   activity (FRE 803(6); MRE 803(6))? That would require scans to be part
   of the clinic's regular practice, made at or near the time, by someone
   with knowledge. Would certification under 902(11) be available?

Expert testimony (FRE 702; MRE 702):

6. Is an expert needed to explain what a flag means, how reliable the
   method is, and what "nothing flagged" does and does not show?

Practicalities:

7. Which courts hear each kind of case locally, and what has each
   accepted before?
8. When should the clinic advise not to uninstall an app until a lawyer or
   advocate is consulted, considering the survivor's safety?
9. Should the phone itself be preserved? Should law enforcement do a
   forensic examination in criminal matters?

Privacy and procedure:

10. How should exports be handed over and stored? They are not encrypted.
11. How do discovery, subpoenas or protective orders over clinic records
    interact with the clinic's privacy duties (DATA_PROTECTION.md)?
12. What retention period applies to evidence copies?
