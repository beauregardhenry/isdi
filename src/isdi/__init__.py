"""
ISDi - Stalkerware Scanner
A privacy and security scanner for mobile devices
"""

__version__ = "1.8.1"
__author__ = "ISDI Contributors"

from isdi.config import get_config, get_data_dir, get_config_dir

__all__ = ["get_config", "get_data_dir", "get_config_dir", "__version__"]
