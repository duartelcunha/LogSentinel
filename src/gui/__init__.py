"""
Log Sentinel v2.0 - GUI Package
================================
Interface gráfica da aplicação.

Author: Duarte Cunha (Nº 2024271)
ISTEC - 2025/2026
"""

from .main_window import LogSentinelApp
from .splash import SplashScreen, SplashManager
from .components import (
    Card, MetricCard, AlertItem, ProgressBar,
    SearchBar, TabView, StatusIndicator
)

__all__ = [
    'LogSentinelApp',
    'SplashScreen',
    'SplashManager',
    'Card',
    'MetricCard',
    'AlertItem',
    'ProgressBar',
    'SearchBar',
    'TabView',
    'StatusIndicator'
]
