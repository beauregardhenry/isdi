# IPV Spyware Discovery (ISDi) Tool

ISDi tool checks Android or iOS devices for apps that can be used for surveillaince
(a.k.a "stalkerware", "spouseware", "spyware" apps). ISDi's technical details are included
in ["Clinical Computer Security for Victims of Intimate Partner Violence"
(USENIX 2019)](https://www.usenix.org/conference/usenixsecurity19/presentation/havron). The blacklist is based
on apps crawled in ["The Spyware Used in Intimate Partner Violence" (IEEE S&P 2018)](https://www.computer.org/csdl/pds/api/csdl/proceedings/download-article/12OmNxWuiny/pdf).

[![Tests](https://github.com/beauregardhenry/isdi/actions/workflows/tests.yml/badge.svg)](https://github.com/beauregardhenry/isdi/actions/workflows/tests.yml)
[![ISDI_Linter](https://github.com/beauregardhenry/isdi/actions/workflows/super-linter.yml/badge.svg)](https://github.com/beauregardhenry/isdi/actions/workflows/super-linter.yml)
[![Sync with IOC stalkerware indicators](https://github.com/beauregardhenry/isdi/actions/workflows/get-stalkerware-indicators.yml/badge.svg)](https://github.com/beauregardhenry/isdi/actions/workflows/get-stalkerware-indicators.yml)

## About this fork

This is a maintained fork of [stopipv/isdi](https://github.com/stopipv/isdi).
It fixes security and detection bugs in upstream 1.0.9, including a command
injection reachable from any web page and a blocklist that flagged no known
stalkerware (see the [releases](https://github.com/beauregardhenry/isdi/releases)).
It is distributed through GitHub releases, not PyPI: the `isdi-scanner`
package on PyPI is upstream's.

Client data is encrypted at rest and raw phone dumps are not kept unless an
evidence copy is asked for; see [DATA_PROTECTION.md](DATA_PROTECTION.md).
For using ISDi records in court, see [COURT_RECORDS.md](COURT_RECORDS.md).

To report a security problem, see [SECURITY.md](SECURITY.md). For anything
else, open an [issue](https://github.com/beauregardhenry/isdi/issues).


## Installing ISDi :computer:

ISDi currently supports **macOS, Linux, and Termux/Android**. If you are using a Windows device, you can use the Windows Subsystem for Linux 2
(WSL2), which can be installed by following [these instructions](https://docs.microsoft.com/en-us/windows/wsl/wsl2-install). After this,
follow the remaining instructions as a Linux user would.

### System Requirements

#### Python
- Python 3.10 or higher is required (tested on 3.10–3.13)
- Check your version: `python3 --version`
- On macOS, install via: `brew install python`
- On Linux (Debian/Ubuntu): `sudo apt install python3 python3-pip`

#### Operating System Dependencies
ISDi needs `adb` for scanning Android devices and `pymobiledevice3` for scanning iOS devices. 

**macOS:**
```bash
brew bundle
# Or manually:
brew install --cask android-platform-tools
```

For iOS device support on macOS, `pymobiledevice3` will be installed automatically with ISDi. For Android device support, ensure `adb` (Android Debug Bridge) is installed via the android-platform-tools above.

**Linux (Debian/Ubuntu):**
```bash
sudo apt install adb
```

For iOS device support on Linux, `pymobiledevice3` will be installed automatically with ISDi. For Android device support, ensure `adb` is installed via the command above.

**Windows Subsystem Linux (v2):**
- Install `adb` and `pymobiledevice3` in Windows and ensure it's in PATH. Do not install them in WSL2, as WSL cannot have access to USB devices. Verify the installation by running `adb.exe` and `pymobiledevice3.exe` in a command prompt terminal. 


**Termux/Android:**
See [TERMUX_INSTALL.md](TERMUX_INSTALL.md) for Android device setup.

### Option 1: Install a release (Recommended)

Install the latest release of this fork straight from GitHub (replace
`v1.4.0` with the newest tag on the
[releases page](https://github.com/beauregardhenry/isdi/releases)):

```bash
pip install "git+https://github.com/beauregardhenry/isdi@v1.4.0"
```

Or, without git, install the wheel attached to the release:

```bash
pip install https://github.com/beauregardhenry/isdi/releases/download/v1.4.0/isdi_scanner-1.4.0-py3-none-any.whl
```

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

ISDi also asks for your name (or `--operator NAME`): it is recorded with
every scan and change, in a tamper-evident audit log.

**First start:** ISDi encrypts all client data, and asks you to choose a
passphrase (at least 12 characters). It then shows a **recovery key** once.
Write it down and keep it safe, away from the computer: without the
passphrase or the recovery key, nobody can read the data, including you.

**Note:** On first run, ISDi will download the app information database (~47MB) from GitHub. This may take a minute depending on your internet connection. An internet connection is required for the first run.

### Command Options

```bash
isdi run                          # Normal mode
isdi run --debug                  # Debug mode (verbose logging)
isdi change-passphrase            # New passphrase (--recovery if it is lost)
isdi export CLIENTID -o file.json # Everything stored about a client, decrypted
isdi erase CLIENTID               # Delete everything stored about a client
isdi audit verify                 # Check the audit log for tampering
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
* `appops`

See details about the services in [notes.md](notes.md)

##### iOS 
Only the `appIds`, and their names. Also, I got "permissions" granted
to the application. I don't know how to get install date, resource usage, etc.
(Any help will be greatly welcomed.)


## Code Structure  

- **`src/isdi/scanner/`** - Core scanning logic
  - `parse_dump.py` - Parses device dumps (Android/iOS)
  - `privacy_scan_android.py` - Android privacy scanning
  - `root_check.py` - Root and jailbreak checks
  - `runcmd.py` - Shell command helpers and input validation
  - `blocklist.py` - Stalkerware/spyware blocklist management
  - `db.py` - SQLite database operations
  - `pmd3_wrapper.py` - Termux-compatible pymobiledevice3 wrapper

- **`src/isdi/web/`** - Flask web application
  - `templates/` - HTML templates for the web UI
  - `static/` - CSS, JavaScript, and images
  - `forms/` - WTForms for consultation forms
  - `model/` - SQLAlchemy models
  - `view/` - Flask route handlers

- **`src/isdi/scripts/`** - Shell scripts for device interaction
  - `ios_scan.sh` - iOS device dump (Android dumps are taken in Python)
  - `ios_mount_linux.sh` - Mounts an iPhone on Linux (not yet wired in)

- **`src/isdi/data/`** - Static data and reference files
  - `app-flags.csv` - App classification metadata
  - `ios_permissions.json` - iOS permission names
  - `ios_device_identifiers.json` - iPhone model names
  - `app-info.db` is not shipped: it is downloaded on first run into the
    cache directory and checked against a pinned SHA-256



See [notes.md](notes.md) for other developer helps.
