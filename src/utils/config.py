"""
Log Sentinel v2.0 - Configuration
==================================
Configurações globais da aplicação.

Author: Duarte Cunha (Nº 2024271)
ISTEC - Instituto Superior de Tecnologias Avançadas de Lisboa
Ano Letivo: 2025/2026
"""

import os
import json
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Dict, Any, Optional


@dataclass
class AppConfig:
    """Configurações da aplicação."""
    
    # === App Info ===
    APP_NAME: str = "Log Sentinel"
    APP_VERSION: str = "2.0.0"
    APP_AUTHOR: str = "Duarte Cunha"
    APP_STUDENT_ID: str = "2024271"
    APP_INSTITUTION: str = "ISTEC - Instituto Superior de Tecnologias Avançadas de Lisboa"
    APP_YEAR: str = "2025/2026"
    
    # === Paths ===
    BASE_DIR: Path = Path(__file__).parent.parent.parent
    DATA_DIR: Path = BASE_DIR / "data"
    LOGS_DIR: Path = DATA_DIR / "logs"
    MODELS_DIR: Path = DATA_DIR / "models"
    REPORTS_DIR: Path = DATA_DIR / "reports"
    ASSETS_DIR: Path = BASE_DIR / "assets"
    ICONS_DIR: Path = ASSETS_DIR / "icons"
    PLUGINS_DIR: Path = BASE_DIR / "src" / "plugins"
    
    # === Database ===
    DB_PATH: Path = DATA_DIR / "sentinel.db"
    
    # === ML Settings ===
    ML_MODEL_PATH: Path = MODELS_DIR / "anomaly_detector.pkl"
    ML_SCALER_PATH: Path = MODELS_DIR / "scaler.pkl"
    ML_RETRAIN_THRESHOLD: int = 1000  # Retrain after N new samples
    
    # === Detection Settings ===
    BRUTE_FORCE_THRESHOLD: int = 5
    BRUTE_FORCE_WINDOW: int = 300  # seconds
    DDOS_THRESHOLD: int = 100
    DDOS_WINDOW: int = 60  # seconds
    SCANNER_THRESHOLD: int = 20
    
    # === UI Settings ===
    WINDOW_WIDTH: int = 1400
    WINDOW_HEIGHT: int = 900
    MIN_WIDTH: int = 1200
    MIN_HEIGHT: int = 700
    SIDEBAR_WIDTH: int = 280
    
    # === Notification Settings ===
    ENABLE_NOTIFICATIONS: bool = True
    NOTIFICATION_TIMEOUT: int = 5  # seconds
    SOUND_ENABLED: bool = True
    
    # === Export Settings ===
    DEFAULT_EXPORT_FORMAT: str = "pdf"  # pdf, csv, json, docx
    
    # === Auto-save Settings ===
    AUTOSAVE_ENABLED: bool = True
    AUTOSAVE_INTERVAL: int = 300  # seconds
    
    def __post_init__(self):
        """Criar diretórios necessários."""
        for dir_path in [self.DATA_DIR, self.LOGS_DIR, self.MODELS_DIR, 
                         self.REPORTS_DIR, self.PLUGINS_DIR]:
            dir_path.mkdir(parents=True, exist_ok=True)


class ConfigManager:
    """Gestor de configurações com persistência."""
    
    def __init__(self, config_path: Optional[Path] = None):
        self.config = AppConfig()
        self.config_path = config_path or (self.config.DATA_DIR / "config.json")
        self._user_settings: Dict[str, Any] = {}
        self.load()
    
    def load(self) -> None:
        """Carrega configurações do ficheiro."""
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    self._user_settings = json.load(f)
            except Exception as e:
                print(f"Erro ao carregar configurações: {e}")
                self._user_settings = {}
    
    def save(self) -> None:
        """Guarda configurações no ficheiro."""
        try:
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.config_path, 'w', encoding='utf-8') as f:
                json.dump(self._user_settings, f, indent=2, default=str)
        except Exception as e:
            print(f"Erro ao guardar configurações: {e}")
    
    def get(self, key: str, default: Any = None) -> Any:
        """Obtém valor de configuração."""
        # Primeiro verifica user settings, depois config default
        if key in self._user_settings:
            return self._user_settings[key]
        return getattr(self.config, key, default)
    
    def set(self, key: str, value: Any) -> None:
        """Define valor de configuração."""
        self._user_settings[key] = value
        self.save()
    
    def reset(self) -> None:
        """Reset para valores padrão."""
        self._user_settings = {}
        self.save()


# Instância global
config = ConfigManager()


# Utilitários
def get_app_info() -> Dict[str, str]:
    """Retorna informações da aplicação."""
    return {
        'name': config.config.APP_NAME,
        'version': config.config.APP_VERSION,
        'author': config.config.APP_AUTHOR,
        'student_id': config.config.APP_STUDENT_ID,
        'institution': config.config.APP_INSTITUTION,
        'year': config.config.APP_YEAR,
    }


def get_copyright_text() -> str:
    """Retorna texto de copyright."""
    info = get_app_info()
    return f"{info['name']} v{info['version']} | {info['author']} (Nº {info['student_id']}) | {info['institution']} | {info['year']}"


if __name__ == "__main__":
    print("Log Sentinel v2.0 - Configuration")
    print("-" * 40)
    info = get_app_info()
    for key, value in info.items():
        print(f"{key}: {value}")
