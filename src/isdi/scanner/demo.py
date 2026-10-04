"""The pretend phone that `isdi run --test` scans."""

from typing import List

from .base import AppScanner


class TestScanner(AppScanner):
    """Test scanner using mock data."""

    def __init__(self):
        super().__init__("android", "test")

    def devices(self) -> List[str]:
        return ["testdevice1", "testdevice2"]

    # What `isdi run --test` shows: ordinary apps, a dual-use app and a
    # stalkerware app from app-flags.csv.
    APPS = [
        "com.android.settings",
        "com.android.chrome",
        "com.google.android.gm",
        "com.whatsapp",
        "com.life360.android.safetymapd",
        "a.tck.lvmchi",
    ]

    def get_apps(self, serialno: str) -> List[str]:
        return list(self.APPS)

    def get_system_apps(self, serialno: str) -> List[str]:
        return self.get_apps(serialno)[:1]

    def get_offstore_apps(self, serialno: str) -> List[str]:
        return []

    def uninstall(self, serial: str, appid: str) -> bool:
        return True
