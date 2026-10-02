"""Configuration management with XDG Base Directory support"""

import os
import sys
import shlex
from pathlib import Path
from typing import Optional
import secrets

__all__ = ["Config", "get_config", "get_data_dir", "get_config_dir"]

# The app metadata database (titles, descriptions, permissions) shown on app
# detail pages. Descriptions are rendered as HTML, so only the exact file
# whose hash is pinned here is accepted. If the release asset is updated
# upstream, download it, check it, and update the hash in the same change.
# Tried in order. The fork's copy (published by the mirror-app-info workflow)
# keeps installs working if upstream removes its asset; the hash below
# decides what is accepted, so where the file comes from does not matter.
APP_INFO_DB_URLS = (
    "https://github.com/beauregardhenry/isdi/releases/download/app-info/app-info.db",
    "https://github.com/stopipv/isdi/releases/download/app-info/app-info.db",
)
APP_INFO_DB_SHA256 = "87ea193f41b35b94f7136560a8b570a2c97a81ccd45bd0dcac4ce4acaa456f38"


def _download_verified(url: str, dst: Path, sha256: str) -> None:
    """Stream url to dst.part and move it into place only if its SHA-256
    matches; otherwise discard it and raise."""
    import hashlib
    import urllib.request

    tmp = dst.with_name(dst.name + ".part")
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            if response.status != 200:
                raise OSError(f"HTTP {response.status}")
            digest = hashlib.sha256()
            with open(tmp, "wb") as f:
                for chunk in iter(lambda: response.read(1 << 20), b""):
                    digest.update(chunk)
                    f.write(chunk)
        # A truncated, replaced or non-database file would otherwise be kept
        # forever: later starts only check that the file is non-empty.
        if digest.hexdigest() != sha256:
            raise ValueError(f"checksum mismatch (got {digest.hexdigest()})")
        os.replace(tmp, dst)
    finally:
        tmp.unlink(missing_ok=True)


def get_platform_dirs():
    """Get platform-specific directories (XDG-compliant)"""

    # Check if running in Termux
    if os.environ.get("PREFIX"):
        # Termux paths
        return {
            "data": Path.home() / "storage" / "shared" / "isdi",
            "config": Path.home() / ".config" / "isdi",
            "cache": Path.home() / ".cache" / "isdi",
            "local_data": Path.home() / ".local" / "share" / "isdi",
        }

    # Standard XDG paths
    data_home = os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")
    config_home = os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")
    cache_home = os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")

    return {
        "data": Path(data_home) / "isdi",
        "config": Path(config_home) / "isdi",
        "cache": Path(cache_home) / "isdi",
        "local_data": Path(data_home) / "isdi",
    }


class Config:
    """Application configuration"""

    def __init__(self, env: str = "production"):
        self.env = env
        self.dirs = get_platform_dirs()

        # Ensure directories exist
        for dir_path in self.dirs.values():
            dir_path.mkdir(parents=True, exist_ok=True)
        # The config dir holds the PII HMAC key and the session secret.
        _restrict_permissions(self.dirs["config"], 0o700)

        # Setup paths
        self.setup_paths()

        # Setup secrets
        self.setup_secrets()

        # Basic settings
        self.TEST = env == "test"
        self.DEBUG = env == "development"

        # App metadata
        self.TITLE = "ISDi - Stalkerware Scanner"
        from isdi import __version__

        self.VERSION = __version__
        self.DEVICE_PRIMARY_USER = "client"  # Default label for device owner

        # Platform detection
        import platform

        self.PLATFORM = platform.system().lower()
        if "microsoft" in platform.release().lower():  # Check for WSL
            self.PLATFORM = "wsl"

        # Additional paths for legacy compatibility
        self.STATIC_DATA = str(self.package_data)
        self.ADB_PATH = "adb" + (".exe" if self.PLATFORM in ("wsl", "win32") else "")
        # Keep dumps under the legacy dumps path for compatibility.
        self.DUMP_DIR = str(self.dumps_dir)
        self.DEV_SUPPORTED = ["android", "ios"]  # Supported device types
        self.SCRIPT_DIR = Path(__file__).parent / "scripts"  # Shell scripts in package

        # iOS tools
        if os.environ.get("PREFIX"):
            py_exec = shlex.quote(sys.executable)

            pyz_path = None
            argv_path = Path(sys.argv[0]).resolve()
            if argv_path.suffix == ".pyz" and argv_path.exists():
                pyz_path = argv_path
            else:
                for entry in sys.path:
                    if entry.endswith(".pyz"):
                        candidate = Path(entry)
                        if candidate.exists():
                            pyz_path = candidate
                            break

            if pyz_path is not None:
                # Shiv bundles packages under site-packages inside the .pyz
                pyz_site = f"{pyz_path}/site-packages"
                pyz_quoted = shlex.quote(str(pyz_site))
                self.LIBIMOBILEDEVICE_PATH = (
                    f"PYTHONPATH={pyz_quoted} {py_exec} -m isdi.scanner.pmd3_wrapper"
                )
            else:
                self.LIBIMOBILEDEVICE_PATH = f"{py_exec} -m isdi.scanner.pmd3_wrapper"
        else:
            if self.PLATFORM != "wsl":
                py_exec = shlex.quote(sys.executable)
                self.LIBIMOBILEDEVICE_PATH = f"{py_exec} -m pymobiledevice3"
            else:
                self.LIBIMOBILEDEVICE_PATH = "pymobiledevice3.exe"

        self.APP_INFO_SQLITE_FILE = f'sqlite:///{self.dirs["cache"]}/app-info.db'

        # Ensure app-info.db exists in cache for runtime lookups
        self._ensure_app_info_db()

        # Logging
        import logging

        self.logging = logging.getLogger("isdi")

    def hmac_serial(self, serial: str) -> str:
        """HMAC hash of device serial for privacy"""
        import hmac
        import hashlib

        key = self.PII_KEY
        return hmac.new(key, serial.encode(), hashlib.sha256).hexdigest()

    def setup_paths(self):
        """Setup all application paths"""
        # Data directories
        self.scans_dir = self.dirs["data"] / "scans"
        self.reports_dir = self.dirs["data"] / "reports"
        self.dumps_dir = self.dirs["data"] / "dumps"
        self.phone_dumps_dir = self.dirs["data"] / "phone_dumps"

        # Config directory
        self.secrets_dir = self.dirs["config"]

        # Cache directory
        self.temp_dir = self.dirs["cache"] / "temp"
        self.logs_dir = self.dirs["cache"] / "logs"

        # Create all directories
        for path in [
            self.scans_dir,
            self.reports_dir,
            self.dumps_dir,
            self.phone_dumps_dir,
            self.temp_dir,
            self.logs_dir,
        ]:
            path.mkdir(parents=True, exist_ok=True)

        # Database
        self.database_path = self.dirs["local_data"] / "database.db"
        self.database_path.parent.mkdir(parents=True, exist_ok=True)

        # Bundled data (read-only, in package)
        self.package_data = Path(__file__).parent / "data"
        self.stalkerware_path = self.package_data / "stalkerware"

        # Legacy compatibility - point to user data dirs
        self.REPORT_PATH = str(self.reports_dir)
        self.SQL_DB_PATH = f"sqlite:///{self.database_path}"

        # App flags file
        self.APP_FLAGS_FILE = self.package_data / "app-flags.csv"
        if not self.APP_FLAGS_FILE.exists():
            # Fallback to old location temporarily
            old_location = (
                Path(__file__).parent.parent.parent / "static_data" / "app-flags.csv"
            )
            if old_location.exists():
                self.APP_FLAGS_FILE = old_location

    def _ensure_app_info_db(self) -> None:
        """Download app-info.db if it is missing, from the first source that
        serves the file with the pinned hash."""
        dst_db = Path(self.dirs["cache"]) / "app-info.db"
        if dst_db.exists() and dst_db.stat().st_size > 0:
            return
        dst_db.parent.mkdir(parents=True, exist_ok=True)
        print("Downloading app-info.db ...")
        for url in APP_INFO_DB_URLS:
            try:
                _download_verified(url, dst_db, APP_INFO_DB_SHA256)
            except Exception as e:
                print(f"  {url}: {e}")
                continue
            print(f"✓ Downloaded app-info.db ({dst_db.stat().st_size} bytes)")
            return
        # Not fatal: scans still work, without app titles and descriptions.
        print(
            "Warning: could not download app-info.db; app details will be "
            f"incomplete. You can place a copy at {dst_db} (SHA-256 "
            f"{APP_INFO_DB_SHA256})."
        )

    def setup_secrets(self):
        """Setup encryption keys and secrets"""
        # PII encryption key
        self.pii_key_file = self.secrets_dir / "pii.key"
        self.PII_KEY = _load_or_create_secret(self.pii_key_file)[:32]

        # Flask secret
        self.flask_secret_file = self.secrets_dir / "flask.secret"
        self.FLASK_SECRET = _load_or_create_secret(self.flask_secret_file)

    def setup_logger(self):
        """Setup logging"""
        import logging

        from isdi.scanner.runcmd import RedactingFilter

        log_file = self.logs_dir / "isdi.log"
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        # Debug output stays on the console: it is not written to disk.
        file_handler.setLevel(logging.INFO)
        handlers = [file_handler, logging.StreamHandler()]
        for h in handlers:
            h.addFilter(RedactingFilter())
        logging.basicConfig(
            level=logging.DEBUG if self.DEBUG else logging.INFO,
            format="%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s",
            handlers=handlers,
        )
        _restrict_permissions(log_file, 0o600)

    @property
    def host(self) -> str:
        # Never listen on the network by default: anyone on the same Wi-Fi
        # could otherwise read scan results or act on the connected phone.
        return "127.0.0.1"

    @property
    def port(self) -> int:
        return 6202 if self.TEST else (6200 if not self.DEBUG else 6201)


def _restrict_permissions(path: Path, mode: int) -> None:
    try:
        if path.stat().st_mode & 0o777 != mode:
            os.chmod(path, mode)
    except OSError:
        pass  # e.g. Termux shared storage does not support chmod


def _load_or_create_secret(path: Path) -> bytes:
    """Read a 32-byte secret, creating it owner-readable only if missing."""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        _restrict_permissions(path, 0o600)
    else:
        with os.fdopen(fd, "wb") as f:
            f.write(secrets.token_bytes(32))
    with open(path, "rb") as f:
        return f.read()


# Global config instance
_config: Optional[Config] = None


def get_config(env: str | None = None) -> Config:
    """Get the global config, creating it for env (default "production").

    Many modules call get_config() at import, so asking for a different env
    after that would silently get the first one (for example, tests writing
    to the real database). That is an error instead.
    """
    global _config
    if _config is None:
        _config = Config(env or "production")
    elif env is not None and env != _config.env:
        raise RuntimeError(
            f"config already created for {_config.env!r}; cannot switch to {env!r}"
        )
    return _config


def get_data_dir() -> Path:
    """Get user data directory"""
    return get_platform_dirs()["data"]


def get_config_dir() -> Path:
    """Get config directory"""
    return get_platform_dirs()["config"]
