"""
Log Sentinel v2.0 - Utils Package
==================================
Utilitários e configurações.

Author: Duarte Cunha (Nº 2024271)
ISTEC - 2025/2026
"""

from .theme import theme, Theme, Icons, Fonts
from .config import config, ConfigManager, get_app_info, get_copyright_text

__all__ = [
    'theme', 'Theme', 'Icons', 'Fonts',
    'config', 'ConfigManager', 'get_app_info', 'get_copyright_text'
]
