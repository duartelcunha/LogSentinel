"""
Log Sentinel v2.0 - Plugins Package
====================================
Sistema de plugins para deteção customizada.

Author: Duarte Cunha (Nº 2024271)
ISTEC - 2025/2026
"""

from .plugin_system import (
    BaseDetectionPlugin,
    DetectionResult,
    PluginInfo,
    PluginManager,
    create_plugin_template
)

__all__ = [
    'BaseDetectionPlugin',
    'DetectionResult',
    'PluginInfo',
    'PluginManager',
    'create_plugin_template'
]
