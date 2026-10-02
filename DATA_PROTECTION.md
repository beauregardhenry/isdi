# Data protection

ISDi holds sensitive information about people who may be at risk from an
abuser: consultation notes, which apps are on their phone, and what the
scan found. This page says what ISDi does to protect that data, what it
does not do, and what the organisation running it still has to do.

It is not legal advice. Whether HIPAA applies depends on whether your
organisation is a covered entity or business associate; GDPR applies if you
process data of people in the EU/EEA or are established there. Ask your
privacy or compliance officer. Software alone cannot make an organisation
compliant with either.

## What ISDi stores, and how

| Data | Where | Protection |
|---|---|---|
| Consultation notes (every field of the form) | database | encrypted |
| Scan results: device model and version, nickname, root/jailbreak findings, notes | database | encrypted |
| Per scan: app ids, flags, remarks, actions taken, and what the phone reported about each app (install dates, permissions, data usage) | database | encrypted |
| Device serials | database | pseudonymised (HMAC-SHA256 with a secret key) |
| Client ids (`YYYYMMDD_NNN`), device type (android/ios), row ids, timestamps | database | **not encrypted**: queries need them. They reveal when consultations and scans took place, and how many. |
| Raw phone dumps | dump directory | exist only while the phone is scanned (see below) |
| Encryption keys | `datakey.json` in the config directory | encrypted with the passphrase and the recovery key |
| Audit log: who did what, when (scans, notes and their edits, uninstalls, exports, erasures) | database | entries chained with HMAC-SHA256; details encrypted, and blanked when a client is erased |
| Log file `isdi.log` | cache directory | no serials, device output, app lists or email addresses |
| App metadata (`app-info.db`) | cache directory | public data, not client data |

### Encryption

- Each value is encrypted with **AES-256-GCM** under one random 256-bit
  data key. GCM also authenticates each value, so altered data is detected,
  and the column name is bound to it, so a value cannot be moved to another
  field unnoticed.
- The data key is stored only in encrypted form, twice:
  - with a key derived from the **passphrase** (scrypt, N=2^17, r=8, p=1),
    entered every time ISDi starts;
  - with a **recovery key**, shown once at setup.

  Without one of the two, the data cannot be decrypted. There is no other
  way in, so if both are lost, the data is lost.
- `isdi change-passphrase` replaces the passphrase without re-encrypting
  the data. Use `--recovery` if the passphrase is lost.
- The serial-pseudonymisation key is kept in the keyfile, encrypted with
  the data key.

### Raw data is not kept

- A phone's raw dump is written to the dump directory (owner-only) while
  it is scanned, and **deleted when the scan ends**, whether it succeeded,
  failed or crashed.
- Any dump still there (after a power cut, or from an older version) is
  deleted at the next start.
- What the details pages need is extracted from the dump and stored,
  encrypted, with the scan.
- Screenshots from the privacy checks are only sent to the browser, never
  saved.
- The parser no longer caches dumps as JSON.
- Plain-text CSV reports are no longer written. Old ones are deleted at
  start: the same data is in the database, and `isdi export` produces it
  on request.

### Upgrading from an earlier version

At the first start after upgrading, ISDi:
- asks for a new passphrase and shows the recovery key;
- encrypts the existing database;
- rewrites the database file so the old plaintext is not left in its free
  pages;
- moves the old pseudonymisation key (`pii.key`) into the keyfile, so
  devices keep their pseudonyms, and deletes the plaintext file;
- deletes old raw dumps and CSV reports.

Copies made before the upgrade, such as **backups, synced folders or old
disk images, are not touched and are still in the clear.** Find and delete
them.

## Rights of the people you serve

- **Access and portability** (GDPR Art. 15 and 20): `isdi export CLIENTID
  -o file.json` writes everything stored about a client, decrypted, as
  JSON. The file is created readable only by you, but it is not encrypted:
  hand it over securely, then delete it.
- **Erasure** (GDPR Art. 17): `isdi erase CLIENTID` deletes the client's
  notes, scans and apps. Deleted rows are overwritten in the database file
  (SQLite `secure_delete`). Deleting one device's scans is also possible
  from the home page.
- **Retention:** ISDi keeps data until it is erased; it never deletes
  anything on its own.

> **Note:** GDPR's storage-limitation principle (Art. 5(1)(e)) says
> personal data must be kept no longer than necessary. Keeping data
> indefinitely needs a documented reason. Otherwise, set a retention period
> and use `isdi erase` to apply it.

## What ISDi does not do

These are gaps you need to cover with how ISDi is run, or that would need
changes to ISDi.

- **No user accounts.** Anyone who can use the computer while ISDi is
  running and unlocked can see all data in the browser.
  - ISDi records the operator's name, given at startup, with every scan and
    audit entry, but it is the operator's own statement, not a login.
  - The audit log (`isdi audit verify`, `isdi audit show`) records actions
    and detects altered, inserted or removed entries. Someone with the
    passphrase could still rebuild the whole log; an earlier export, which
    records the newest entry, would then no longer match.
  - HIPAA's unique user identification requirement (45 CFR
    164.312(a)(2)(i)) is therefore still not met by ISDi itself, and the
    audit log covers only part of its audit-control requirement (164.312(b)).
  - Use a separate OS account for ISDi.
  - Lock the screen when away.
  - Stop ISDi (Ctrl-C) when the consultation ends.
- **Data is decrypted while ISDi runs.** It is in memory and shown in the
  browser; encryption protects the data at rest, not a running, unlocked
  session.
- **The browser history records links that contain a device serial and app
  ids** (for example `/details/app/android?serial=…&appId=…`). Use a
  private browsing window, or clear the history after each consultation.
  Pages are sent with `Cache-Control: no-store`, so their content is not
  cached.
- **Deleting a file does not reliably erase it** on SSDs and journaling
  file systems. Raw dumps are on disk, unencrypted, for the length of a
  scan. **Use full-disk encryption** (FileVault, BitLocker, LUKS, or the
  phone's own encryption on Termux): it is what protects anything the file
  system leaves behind, and a lost or stolen laptop.
- **On Termux, the data directory is on shared storage**, where other apps
  with storage permission can read files. The database is encrypted, but
  raw dumps there are not, during a scan.
- **`ISDI_PASSPHRASE`.** Setting it skips the passphrase prompt, but other
  programs running as the same user can read it. Avoid it outside testing.
- **Breach notification.** Under GDPR Art. 34(3)(a), notifying the people
  affected may not be required if the data was unintelligible to the person
  who obtained it, for example strongly encrypted with an uncompromised key.
  That only holds if the passphrase and recovery key were not exposed too.

## For the organisation

- Decide whether HIPAA and/or GDPR apply. Record the legal basis for
  processing. Under GDPR, data about people experiencing abuse is likely to
  need a data protection impact assessment (Art. 35).
- Keep the recovery key offline and with someone accountable, separate from
  the computer.
- Use full-disk encryption on every computer that runs ISDi, and keep
  backups of the database encrypted as well.
- Decide who may run ISDi, and how exports are handed over and deleted.
