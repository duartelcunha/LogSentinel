"""
Log Sentinel v2.0 - Core Package
=================================
Módulos principais do sistema.

Author: Duarte Cunha (Nº 2024271)
ISTEC - 2025/2026
"""

from .database import DatabaseManager
from .parser import LogParser, LogEntry
from .engine import DetectionEngine, Anomaly, Severity, AnomalyType

# Novos módulos v2.0
try:
    from .realtime_monitor import RealTimeMonitor, LogEvent
    REALTIME_AVAILABLE = True
except ImportError:
    REALTIME_AVAILABLE = False

try:
    from .siem_integration import SIEMIntegration, SIEMEvent, SIEMType
    SIEM_AVAILABLE = True
except ImportError:
    SIEM_AVAILABLE = False

try:
    from .extended_parsers import ExtendedLogParser, ExtendedLogEntry
    EXTENDED_PARSERS_AVAILABLE = True
except ImportError:
    EXTENDED_PARSERS_AVAILABLE = False

__all__ = [
    'DatabaseManager',
    'LogParser',
    'LogEntry',
    'DetectionEngine',
    'Anomaly',
    'Severity',
    'AnomalyType',
    'RealTimeMonitor',
    'LogEvent',
    'SIEMIntegration',
    'SIEMEvent',
    'SIEMType',
    'ExtendedLogParser',
    'ExtendedLogEntry',
    'REALTIME_AVAILABLE',
    'SIEM_AVAILABLE',
    'EXTENDED_PARSERS_AVAILABLE'
]
