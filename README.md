# ISDi: IPV Spyware Discovery

ISDi checks an Android phone or iPhone for stalkerware: apps and settings
that let someone else watch the person who carries it. It is built for
staff at tech-abuse clinics and domestic-violence services, who run it on
a laptop with the client present and go through the results together.
It runs in a browser on that laptop, and client data stays on it.

[![Tests](https://github.com/beauregardhenry/isdi/actions/workflows/tests.yml/badge.svg)](https://github.com/beauregardhenry/isdi/actions/workflows/tests.yml)
[![ISDI_Linter](https://github.com/beauregardhenry/isdi/actions/workflows/super-linter.yml/badge.svg)](https://github.com/beauregardhenry/isdi/actions/workflows/super-linter.yml)
[![Sync with IOC stalkerware indicators](https://github.com/beauregardhenry/isdi/actions/workflows/get-stalkerware-indicators.yml/badge.svg)](https://github.com/beauregardhenry/isdi/actions/workflows/get-stalkerware-indicators.yml)

## What it finds

- **Known stalkerware, by name and by signing certificate.** The list comes
  from the [stalkerware-indicators](https://github.com/AssoEchap/stalkerware-indicators)
  project and is synced weekly. On Android, matching the certificate catches copies
  that were renamed to avoid the list.
- **Apps that hide and hold powers (Android).** An app installed outside the store,
  with no icon in the app list, that holds accessibility, notification
  access or device administrator rights. This does not depend on any list.
- **Phone-wide control.** Device owner and Android special access; iPhone
  supervision and configuration profiles; rooting and jailbreaks.
- **Apps named to blend in.** iPhone apps are listed by their home-screen
  name, which is how the client knows them.

Each release ends with a [detection scorecard](https://github.com/beauregardhenry/isdi/releases/latest).
In the latest one, every listed package (615) and certificate (473) is
matched, and so are 98% of the known stalkerware samples that record a
package or certificate (1,562 of 1,594). The samples it misses each use
their own random name and key, which no list can match. The checks for
hidden apps and powers are there for those.

## For staff

Start with the one-page [quick start for advocates](docs/STAFF_QUICKSTART.md).
ISDi keeps a consultation record per client (questionnaire, account
checks, notes, screenshots) and produces a report and a take-home copy.

Client data is encrypted at rest, every page needs a sign-in, and raw
phone dumps exist only while the phone is scanned; see [DATA_PROTECTION.md](DATA_PROTECTION.md). For using ISDi
records in court, see [COURT_RECORDS.md](COURT_RECORDS.md) (one-page
version for counsel: [docs/COUNSEL_BRIEF.md](docs/COUNSEL_BRIEF.md)).

## About this fork

This is a maintained fork of [stopipv/isdi](https://github.com/stopipv/isdi),
the tool described in ["Clinical Computer Security for Victims of Intimate
Partner Violence" (USENIX Security 2019)](https://www.usenix.org/conference/usenixsecurity19/presentation/havron).
Its original app list came from ["The Spyware Used in Intimate Partner
Violence" (IEEE S&P 2018)](https://www.computer.org/csdl/pds/api/csdl/proceedings/download-article/12OmNxWuiny/pdf).
The fork fixes security and detection bugs in upstream 1.0.9, including a
command injection reachable from any web page and a blocklist that
flagged no known stalkerware. It also absorbed the consultation workflow
of the retired Sherloc fork.

It is distributed through [GitHub releases](https://github.com/beauregardhenry/isdi/releases),
not PyPI: the `isdi-scanner` package on PyPI is upstream's. A patch
release follows each blocklist change, so upgrade regularly. What each
release changes for staff is in [CHANGELOG.md](CHANGELOG.md).

To help confirm ISDi's checks on real phones, see [FIELD_TEST.md](FIELD_TEST.md)
(`isdi field-test`, on a test phone). To have the Spanish translation
reviewed, see [docs/review/](docs/review/README.md). To report a security
problem, see [SECURITY.md](SECURITY.md). For anything else, open an
[issue](https://github.com/beauregardhenry/isdi/issues).

**Upgrading from before 1.5:** every page now needs a sign-in. The first
time ISDi starts after the upgrade, it asks for a first account
(username, full name, password) in the terminal; add one for each other
person with `isdi user add`.


## Installing ISDi :computer:

ISDi currently supports **macOS, Linux, and Termux/Android**. If you are using a Windows device, you can use the Windows Subsystem for Linux 2
(WSL2), which can be installed by following [these instructions](https://docs.microsoft.com/en-us/windows/wsl/wsl2-install). After this,
follow the remaining instructions as a Linux user would.

### System Requirements

#### Python
- Python 3.11 or higher is required (tested on 3.11–3.13)
- Check your version: `python3 --version`
- On macOS, install via: `brew install python`
- On Linux (Debian/Ubuntu): `sudo apt install python3 python3-pip`. Ubuntu
  22.04's `python3` is 3.10, which is too old: use Ubuntu 24.04 or later,
  or install a newer Python alongside it.

#### Operating System Dependencies
ISDi needs `adb` for scanning Android devices and `pymobiledevice3` for scanning iOS devices. 

**macOS:**
```bash
brew bundle   # in the isdi folder: adb, and Pango for PDF reports
# Or manually:
brew install --cask android-platform-tools
brew install pango
```

For iOS device support on macOS, `pymobiledevice3` will be installed automatically with ISDi. For Android device support, ensure `adb` (Android Debug Bridge) is installed via the android-platform-tools above.

**Linux (Debian/Ubuntu):**
```bash
sudo apt install adb
# For PDF reports (WeasyPrint), on Debian 11 or newer:
sudo apt install libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz-subset0
# On Ubuntu 20.04 or newer, add libharfbuzz0b.
```

For iOS device support on Linux, `pymobiledevice3` will be installed automatically with ISDi. For Android device support, ensure `adb` is installed via the command above.

**Windows Subsystem Linux (v2):**
- Install `adb` and `pymobiledevice3` in Windows and ensure it's in PATH. Do not install them in WSL2, as WSL cannot have access to USB devices. Verify the installation by running `adb.exe` and `pymobiledevice3.exe` in a command prompt terminal. 


**Termux/Android:**
See [TERMUX_INSTALL.md](TERMUX_INSTALL.md) for Android device setup.

### Option 1: Install a release (Recommended)

Install the latest release of this fork straight from GitHub (replace
`v1.12.0` with the newest tag on the
[releases page](https://github.com/beauregardhenry/isdi/releases)):

```bash
pip install "git+https://github.com/beauregardhenry/isdi@v1.12.0"
```

Or, without git, install the wheel attached to the release:

```bash
pip install https://github.com/beauregardhenry/isdi/releases/download/v1.12.0/isdi_scanner-1.12.0-py3-none-any.whl
```

To install exactly the dependency versions the release was tested with
(recommended for clinics; releases from 1.7.0 on), add its
`constraints.txt`:

```bash
pip install -c https://github.com/beauregardhenry/isdi/releases/download/v1.12.0/constraints.txt \
  https://github.com/beauregardhenry/isdi/releases/download/v1.12.0/isdi_scanner-1.12.0-py3-none-any.whl
```

To make PDFs of the consultation report, install the `report` extra
(WeasyPrint and pypdf; WeasyPrint needs Pango, above):

```bash
pip install -c https://github.com/beauregardhenry/isdi/releases/download/v1.12.0/constraints.txt \
  "isdi-scanner[report] @ https://github.com/beauregardhenry/isdi/releases/download/v1.12.0/isdi_scanner-1.12.0-py3-none-any.whl"
```

Without it, everything else works, and the report can be printed or
saved as PDF from the browser.

> **Note:** this fork uses the same package name, `isdi-scanner`, as
> upstream's PyPI release. Installing it replaces upstream's version, but
> `pip install -U isdi-scanner` (without a URL) would download upstream's
> 1.0.9 from PyPI again. Always upgrade with one of the commands above.

### Option 2: Install from Source (Development)

Clone the repository and install in development mode:

```bash
git clone https://github.com/beauregardhenry/isdi.git
cd isdi
pip install -e ".[dev]"
``` 

## Running ISDi

After ISDi is installed, with an Android or iOS device plugged in and unlocked, run:

```bash
isdi run
```

ISDi asks for its passphrase, then starts a local web server on port 6200. Open your browser to `http://localhost:6200` for the ISDi UI. In debug mode, the server is on port 6201, and in test mode (`--test`) on 6202.

Each person signs in with their own account; what they do is recorded
under their name in a tamper-evident audit log. On the first start, ISDi
asks you to create the first account. Add others with `isdi user add`.

**First start:** ISDi encrypts all client data, and asks you to choose a
passphrase (at least 12 characters). It then shows a **recovery key** once.
Write it down and keep it safe, away from the computer: without the
passphrase or the recovery key, nobody can read the data, including you.

**Note:** When ISDi starts and the app information database (store titles and descriptions, about 47 MB) is missing, it downloads it from GitHub and checks it against a pinned SHA-256. Nothing is downloaded at any other time. Scans work without it: app pages then show only what the phone reports. Each start also asks GitHub, in the background, for the latest release's version, and the home page warns when a newer release exists. To start without contacting GitHub at all, use `isdi run --offline`; to download the database ahead of time, run `isdi fetch-app-info`. See "What ISDi sends over the network" in [DATA_PROTECTION.md](DATA_PROTECTION.md).

### Consultation record

"Consultation record" on the home page keeps what staff go through with
the client of the session, next to that client's scans:

- the technology assessment questionnaire (devices, passwords, sharing,
  smart home, children's devices, legal proceedings) and the risks the
  answers point to;
- account checks (logins and devices, password, recovery settings,
  two-factor authentication, security questions);
- devices, from a scan or added by hand, and the questions asked about
  each app;
- screenshots, taken from a connected Android phone or uploaded;
- notes for the whole consultation.

The report puts it together for staff, or as a take-home copy that
leaves out the client's name, the consultant's notes and the names of
the clinic and of ISDi. It can be
downloaded as a PDF, optionally protected with a password (the `report`
extra, above). Like the rest of the client's records, the consultation
record is encrypted, and it is exported and erased with the client.

This part of ISDi came from [Sherloc](https://github.com/WISPR-lab/sherloc),
which is no longer needed alongside ISDi.

### Command Options

```bash
isdi run                          # Normal mode
isdi run --debug                  # Debug mode (verbose logging)
isdi run --offline                # Never contact GitHub (no download, no release check)
isdi run --ram-dumps              # Keep raw phone data in memory, never on disk
                                  #   (Linux, macOS; see DATA_PROTECTION.md)
isdi fetch-app-info               # Download app-info.db if missing
isdi change-passphrase            # New passphrase (--recovery if it is lost)
isdi user add USERNAME            # Create a staff account (--supervisor to
                                  #   open every client; also: list, role,
                                  #   disable, enable, reset-password)
isdi backup -o FILE               # Encrypted backup of all ISDi data
isdi restore FILE                 # Restore it (here or on a new computer)
isdi export CLIENTID -o file.json # Everything stored about a client, decrypted
isdi erase CLIENTID               # Delete everything stored about a client
isdi reset -o FILE                # Delete ALL data (backup first; asks to confirm)
isdi audit verify                 # Check the audit log for tampering
isdi audit anchor -o FILE         # Signed record of the log, to send off-site
isdi audit verify --anchor FILE   # Check the log still matches that record
isdi audit show [CLIENTID]        # Who did what, and when
isdi evidence export SCANID -o DIR # Signed evidence package for one scan
isdi verify PATH                  # Check a signed export or package
isdi signing-key                  # This installation's signing-key fingerprint
isdi --help                       # Show all options
```

Then navigate to the URL shown in the terminal. Click on `"Scan Instructions"` and follow the instructions to prepare your device for the scan.

It should look something like this:

![Phone Scanner UI before scan](src/isdi/web/static/ISDi_before_scan.png "Phone Scanner
UI before scan")

Connect a device and click on the suitable button `Android` or `iOS`. Give it a
nickname and click "Scan now". (**Please connect one device at a time.**) It
will take a few seconds for the scan to complete. We are working to have all
scan results done at once on Android, but for the time being please leave the
device plugged in when clicking on apps on the scan results table.

After the scan, the UI will look something like this:

![Phone Scanner UI after scan](src/isdi/web/static/ISDi_after_scan.png "Phone Scanner
UI")


## Debugging Tips

### Android
Check device connection:
```bash
adb devices
```

### iOS  
Check device connection:
```bash
pymobiledevice3 usbmux list
```

### General
- Run ISDi with `--debug` flag for verbose logging
- Check logs in `~/.local/share/isdi/logs/`
- File issues on [GitHub](https://github.com/beauregardhenry/isdi/issues) with error messages

### Termux/Android
See [TERMUX_INSTALL.md](TERMUX_INSTALL.md) for Termux-specific troubleshooting.

## Downloaded data ## 
ISDi reads the following from a phone. The raw dump exists only while the
phone is scanned; what the scan keeps (the app list, flags, and per-app
details such as install dates) is stored encrypted in the database, with the
consultation notes. See [DATA_PROTECTION.md](DATA_PROTECTION.md).

##### Android 
The services that we can dump safely using `dumpsys` are the
following.
* Application static details: `package` Sensor and configuration info:
* `location`, `media.camera`, `netpolicy`, `mount` Resource information:
* `cpuinfo`, `dbinfo`, `meminfo` Resource consumption: `procstats`,
* `batterystats`, `netstats`, `usagestats` App running information: `activity`,
* `appops` Device administrators: `device_policy`

The secure settings (`settings list secure`) are read too: they list the
apps allowed to use accessibility services and to read notifications.
Apps the user installed that hold either power, or are device
administrators, are flagged (`accessibility`, `notification-access`,
`device-admin`). These are powers monitoring apps rely on, but many
legitimate apps hold them too (password managers, smartwatch apps, work
profiles), so a flag is a reason to ask about the app, not a finding by
itself. Preinstalled (system) apps are not flagged.

See details about the services in [notes.md](notes.md)

##### iOS 
The `appIds`, their names, and the "permissions" granted to each app;
install dates and resource use are not available.

ISDi also asks the phone whether it is supervised, and which
configuration profiles are installed (pymobiledevice3's
`MobileConfigService`, read-only). On iPhones, monitoring is often done
through management rather than an app. Work and school phones are often
managed for ordinary reasons. If the phone is locked or does not trust
the computer, the result says "could not check", never "not managed".
This check has not yet been confirmed on a range of real iPhones.


## Code Structure  

- **`src/isdi/cli/`** - The `isdi` command line
  - `server.py` - `run`, `info`, `paths`
  - `accounts.py` - `user ...`
  - `keys.py` - passphrase, signing key, `backup`, `restore`, `reset`
  - `records.py` - `export`, `erase`, `evidence ...`, `verify`, `audit ...`
  - `fieldtest.py` - `field-test`

- **Core modules in `src/isdi/`** - `crypto.py` (encryption and signing),
  `users.py` (accounts and roles), `audit.py` (the audit log), `evidence.py`
  (evidence copies and signed packages), `backup.py` (encrypted backups),
  `data_protection.py` (removing plaintext leftovers), `fieldtest.py` (the
  field test's report)

- **`src/isdi/scanner/`** - Core scanning logic
  - `base.py` - The scanner base class and the raw dump files a scan handles
  - `android.py`, `ios.py` - The Android (adb) and iOS (pymobiledevice3) scanners
  - `demo.py` - The pretend phone scanned by `isdi run --test`
  - `parse_dump.py` - Parses device dumps (Android/iOS)
  - `privacy_scan_android.py` - Android privacy scanning
  - `root_check.py` - Root and jailbreak checks
  - `ios_management.py` - iPhone supervision and configuration profiles
  - `runcmd.py` - Shell command helpers and input validation
  - `blocklist.py` - Stalkerware/spyware blocklist management
  - `db.py` - SQLite database operations
  - `pmd3_wrapper.py` - Termux-compatible pymobiledevice3 wrapper

- **`src/isdi/web/`** - Flask web application
  - `templates/` - HTML templates for the web UI
  - `static/` - CSS, JavaScript, and images
  - `forms/` - WTForms for consultation forms
  - `view/` - Flask route handlers

- **`src/isdi/scripts/`** - Shell scripts for device interaction
  - `ios_scan.sh` - iOS device dump (Android dumps are taken in Python)

- **`src/isdi/data/`** - Static data and reference files
  - `app-flags.csv` - App classification metadata
  - `ios_permissions.json` - iOS permission names
  - `ios_device_identifiers.json` - iPhone model names
  - `app-info.db` is not shipped: it is downloaded on first run into the
    cache directory and checked against a pinned SHA-256



See [notes.md](notes.md) for other developer helps.
