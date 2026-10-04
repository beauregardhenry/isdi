"""Phone scanning: Android (adb) and iOS (pymobiledevice3).

- base: AppScanner, and the raw dump files a scan writes and deletes;
- android, ios: the scanners for each kind of phone;
- demo: the pretend phone of `isdi run --test`.
"""

from .base import (  # noqa: F401
    AppScanner,
    _pseudonym,
    cfg,
    purge_raw_dumps,
    raw_path,
)
from .android import AndroidScanner  # noqa: F401
from .ios import IosScanner  # noqa: F401
from .demo import TestScanner  # noqa: F401
