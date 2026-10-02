#!/usr/bin/env python3
"""Check that an installed isdi-scanner package can start and serve pages.

Run it with the interpreter of an environment where the wheel (not the
source tree) is installed, from outside the repository. It catches files
missing from the wheel: templates, static files, the iOS dump
script and the data files.
"""

import os
import sys
import tempfile
from pathlib import Path

home = Path(tempfile.mkdtemp(prefix="isdi-smoke-"))
for var in ("XDG_DATA_HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME"):
    os.environ[var] = str(home / var.lower())
os.environ.pop("PREFIX", None)

import isdi  # noqa: E402
from isdi.config import get_config  # noqa: E402

pkg = Path(isdi.__file__).parent
if "site-packages" not in pkg.parts:
    sys.exit(f"isdi is imported from {pkg}, not from an installed wheel")

config = get_config("test")

from isdi import crypto  # noqa: E402

crypto.setup(config.keyfile, "smoke test passphrase")
for f in (
    config.SCRIPT_DIR / "ios_scan.sh",
    config.APP_FLAGS_FILE,
    pkg / "data" / "ios_permissions.json",
    pkg / "data" / "ios_device_identifiers.json",
):
    if not f.is_file():
        sys.exit(f"missing from the wheel: {f}")

from isdi.app import create_app  # noqa: E402

client = create_app(config).test_client()
for url in ("/", "/instruction", "/static/myjscript.js", "/static/bootstrap.min.css"):
    status = client.get(url).status_code
    if status != 200:
        sys.exit(f"GET {url} returned {status}")

print(f"isdi {isdi.__version__} from {pkg}: OK")
