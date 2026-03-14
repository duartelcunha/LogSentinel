"""
Log Sentinel v2.0 - Theme & Colors
===================================
Sistema de cores profissional e minimalista.

Author: Duarte Cunha (Nº 2024271)
ISTEC - Instituto Superior de Tecnologias Avançadas de Lisboa
Ano Letivo: 2025/2026
"""

from dataclasses import dataclass
from typing import Dict, Tuple


@dataclass
class Theme:
    """
    Tema profissional para a aplicação.
    Cores neutras e elegantes com toques de azul para destaque.
    """
    
    # === Backgrounds ===
    BG_PRIMARY: str = "#0f172a"      # Fundo principal (azul muito escuro)
    BG_SECONDARY: str = "#1e293b"    # Fundo secundário (painéis)
    BG_TERTIARY: str = "#334155"     # Fundo terciário (cards)
    BG_CARD: str = "#1e293b"         # Fundo de cards
    BG_HOVER: str = "#374151"        # Hover state
    BG_INPUT: str = "#0f172a"        # Campos de input
    
    # === Texto ===
    TEXT_PRIMARY: str = "#f1f5f9"    # Texto principal (quase branco)
    TEXT_SECONDARY: str = "#94a3b8"  # Texto secundário
    TEXT_MUTED: str = "#64748b"      # Texto desabilitado/muted
    TEXT_INVERSE: str = "#0f172a"    # Texto em fundo claro
    
    # === Accent Colors === (Verde do Logo)
    ACCENT_PRIMARY: str = "#2E9E4B"  # Verde principal do logo
    ACCENT_SECONDARY: str = "#4ADE80" # Verde claro
    ACCENT_HOVER: str = "#1E7B37"    # Verde hover
    
    # === Severity Colors ===
    CRITICAL: str = "#ef4444"        # Vermelho
    HIGH: str = "#f97316"            # Laranja
    MEDIUM: str = "#eab308"          # Amarelo
    LOW: str = "#22c55e"             # Verde
    INFO: str = "#2E9E4B"            # Verde (cor do logo)
    
    # === Status Colors ===
    SUCCESS: str = "#22c55e"         # Verde sucesso
    WARNING: str = "#f59e0b"         # Amarelo warning
    ERROR: str = "#ef4444"           # Vermelho erro
    
    # === Borders ===
    BORDER_PRIMARY: str = "#334155"  # Borda principal
    BORDER_SECONDARY: str = "#475569" # Borda secundária
    BORDER_ACCENT: str = "#3b82f6"   # Borda com accent
    
    # === Chart Colors ===
    CHART_COLORS: Tuple[str, ...] = (
        "#3b82f6",  # Azul
        "#22c55e",  # Verde
        "#f59e0b",  # Amarelo
        "#ef4444",  # Vermelho
        "#8b5cf6",  # Roxo
        "#06b6d4",  # Cyan
        "#f97316",  # Laranja
        "#ec4899",  # Rosa
    )
    
    # === Fonts ===
    FONT_FAMILY: str = "Segoe UI"
    FONT_FAMILY_MONO: str = "Consolas"
    FONT_SIZE_XS: int = 10
    FONT_SIZE_SM: int = 11
    FONT_SIZE_MD: int = 12
    FONT_SIZE_LG: int = 14
    FONT_SIZE_XL: int = 16
    FONT_SIZE_2XL: int = 20
    FONT_SIZE_3XL: int = 24
    FONT_SIZE_4XL: int = 32
    
    # === Spacing ===
    SPACING_XS: int = 4
    SPACING_SM: int = 8
    SPACING_MD: int = 12
    SPACING_LG: int = 16
    SPACING_XL: int = 24
    SPACING_2XL: int = 32
    
    # === Border Radius ===
    RADIUS_SM: int = 4
    RADIUS_MD: int = 8
    RADIUS_LG: int = 12
    RADIUS_XL: int = 16
    RADIUS_FULL: int = 9999
    
    @classmethod
    def get_severity_color(cls, severity: str) -> str:
        """Retorna a cor correspondente à severidade."""
        severity_map = {
            'CRITICAL': cls.CRITICAL,
            'HIGH': cls.HIGH,
            'MEDIUM': cls.MEDIUM,
            'LOW': cls.LOW,
            'INFO': cls.INFO,
        }
        return severity_map.get(severity.upper(), cls.TEXT_SECONDARY)
    
    @classmethod
    def get_severity_bg(cls, severity: str) -> str:
        """Retorna cor de background suave para severidade."""
        bg_map = {
            'CRITICAL': '#7f1d1d',  # red-900
            'HIGH': '#7c2d12',      # orange-900
            'MEDIUM': '#713f12',    # yellow-900
            'LOW': '#14532d',       # green-900
            'INFO': '#1e3a8a',      # blue-900
        }
        return bg_map.get(severity.upper(), cls.BG_TERTIARY)


# Instância global do tema
theme = Theme()


# Constantes de ícones Unicode (para uso sem imagens)
class Icons:
    """Ícones Unicode para a interface."""
    
    # Status
    SUCCESS = "✓"
    ERROR = "✕"
    WARNING = "⚠"
    INFO = "ℹ"
    
    # Navigation
    HOME = "⌂"
    SETTINGS = "⚙"
    SEARCH = "🔍"
    FILTER = "⊕"
    
    # Actions
    UPLOAD = "↑"
    DOWNLOAD = "↓"
    REFRESH = "↻"
    DELETE = "✕"
    EDIT = "✎"
    SAVE = "💾"
    EXPORT = "📤"
    
    # Security
    SHIELD = "🛡"
    LOCK = "🔒"
    UNLOCK = "🔓"
    KEY = "🔑"
    
    # Analysis
    SCAN = "◎"
    CHART = "📊"
    GRAPH = "📈"
    REPORT = "📋"
    
    # Alerts
    ALERT = "🔔"
    CRITICAL = "🔴"
    HIGH = "🟠"
    MEDIUM = "🟡"
    LOW = "🟢"
    
    # Misc
    OWL = "🦉"
    CLOCK = "⏱"
    CALENDAR = "📅"
    USER = "👤"
    IP = "🌐"
    FILE = "📄"
    FOLDER = "📁"
    DATABASE = "🗄"
    TERMINAL = "⬛"
    PLAY = "▶"
    PAUSE = "⏸"
    STOP = "⏹"


class Fonts:
    """Configurações de fonte para customtkinter."""
    
    @staticmethod
    def title():
        import customtkinter as ctk
        return ctk.CTkFont(family=theme.FONT_FAMILY, size=theme.FONT_SIZE_3XL, weight="bold")
    
    @staticmethod
    def heading():
        import customtkinter as ctk
        return ctk.CTkFont(family=theme.FONT_FAMILY, size=theme.FONT_SIZE_XL, weight="bold")
    
    @staticmethod
    def subheading():
        import customtkinter as ctk
        return ctk.CTkFont(family=theme.FONT_FAMILY, size=theme.FONT_SIZE_LG, weight="bold")
    
    @staticmethod
    def body():
        import customtkinter as ctk
        return ctk.CTkFont(family=theme.FONT_FAMILY, size=theme.FONT_SIZE_MD)
    
    @staticmethod
    def small():
        import customtkinter as ctk
        return ctk.CTkFont(family=theme.FONT_FAMILY, size=theme.FONT_SIZE_SM)
    
    @staticmethod
    def mono():
        import customtkinter as ctk
        return ctk.CTkFont(family=theme.FONT_FAMILY_MONO, size=theme.FONT_SIZE_MD)
    
    @staticmethod
    def mono_small():
        import customtkinter as ctk
        return ctk.CTkFont(family=theme.FONT_FAMILY_MONO, size=theme.FONT_SIZE_SM)


if __name__ == "__main__":
    print("Log Sentinel v2.0 - Theme Configuration")
    print("-" * 40)
    print(f"Primary Background: {theme.BG_PRIMARY}")
    print(f"Accent Color: {theme.ACCENT_PRIMARY}")
    print(f"Critical Color: {theme.CRITICAL}")
    print(f"Success Color: {theme.SUCCESS}")
