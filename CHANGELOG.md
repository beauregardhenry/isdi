# Changes

What each release changes for the people using ISDi. Each GitHub release
starts with its section from this file, followed by the list of merged
pull requests. Patch releases that only update the stalkerware blocklist
have no section here.

## 1.7.0

- **`isdi reset` is harder to run by mistake.** It now needs the
  passphrase, a backup first (`-o FILE`, or `--no-backup` to skip it), and
  typing `DELETE EVERYTHING`. The reset is recorded in the audit log, which
  the backup keeps. To delete one client's data, use `isdi erase`.
- Scans parse each phone dump once instead of twice, which roughly halves
  that part of an Android scan.
- An app's details page no longer shows an empty highlighted summary: it
  falls back to the app's name. A malformed data-usage line no longer
  hides the "data used" rows, and an empty dump section can no longer
  replace the data from a full one.
- **Reproducible installs.** Each release now has a `constraints.txt`
  listing the dependency versions it was tested with on each Python
  version; see the README for the install command.

## 1.6.0

- **Backups.** `isdi backup -o FILE` writes all ISDi data to one encrypted
  file; `isdi restore FILE` brings it back, on this computer or a new one,
  with the passphrase or the recovery key. `isdi run` reminds you when the
  last backup is more than 7 days old. Keep backups away from the computer.
- **ISDi only runs on this computer.** `isdi run --host` now refuses any
  address other than 127.0.0.1, ::1 or localhost.
- **Roles.** New accounts are staff: they open only the clients they
  started. Supervisors open every client. Existing accounts become
  supervisors, so nothing changes for them until you choose; use
  `isdi user role USERNAME staff` for anyone who should not see other
  clients, and `isdi user add --supervisor` for new supervisors.
- Scans can only be changed within their own client's session, and
  "Delete" on a device removes only the current client's scans of it.
  Two people starting new clients at the same time no longer get the same
  client id.
- An app's details page now always shows what that scan recorded. Before,
  if the phone had been scanned again later (for any client), it showed
  the later scan's details.
- If a command to the phone fails, ISDi no longer records the error text
  as the phone's answer (for example as its model name).
- The nickname typed for a phone is kept on the page after a scan.
- iPhone app details no longer show empty "jailbroken" and "phone_kind"
  rows. (Jailbreak checks are made per phone, at the top of the scan.)
- **Termux:** raw phone dumps are now kept in Termux's private storage
  during a scan, not in shared storage. Any left in shared storage by an
  older version are deleted at the next start.

## 1.5.0

- **Everyone signs in.** Each person needs their own account. The first
  start after upgrading asks for a first account in the terminal; add the
  others with `isdi user add USERNAME`. ISDi no longer asks for a name at
  startup.
- Sessions end after 15 minutes without activity, on sign-out, or when the
  account is disabled or its password changes. 5 wrong passwords in a row
  lock an account for 15 minutes.
- **Evidence copies of Android scans can be kept unredacted**, with the
  email addresses of the accounts on the phone (a new box under "Keep an
  encrypted evidence copy").
- **Audit-log anchors:** `isdi audit anchor -o FILE` writes a small signed
  record to send outside the clinic, for example to counsel;
  `isdi audit verify --anchor FILE` later shows whether the log was
  changed since.
