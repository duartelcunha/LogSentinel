"""
Log Sentinel v2.0 - ML Package
===============================
Machine Learning para deteção de anomalias.

Author: Duarte Cunha (Nº 2024271)
ISTEC - 2025/2026
"""

from .anomaly_detector import (
    AnomalyDetector,
    FeatureExtractor,
    MLPrediction,
    SKLEARN_AVAILABLE
)

__all__ = [
    'AnomalyDetector',
    'FeatureExtractor', 
    'MLPrediction',
    'SKLEARN_AVAILABLE'
]
