"""
Log Sentinel v2.0 - Main Window
================================
Interface gráfica principal com design profissional.

Author: Duarte Cunha (Nº 2024271)
ISTEC - Instituto Superior de Tecnologias Avançadas de Lisboa
Ano Letivo: 2025/2026
"""

import customtkinter as ctk
from tkinter import filedialog, messagebox
from PIL import Image
import threading
import os
import sys
import json
from datetime import datetime
from typing import Optional, List, Dict
from pathlib import Path

# Imports internos
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.theme import theme, Icons, Fonts
from utils.config import config, get_app_info, get_copyright_text
from core.database import DatabaseManager
from core.engine import DetectionEngine, Anomaly, Severity, AnomalyType
from core.exporter import ReportExporter
from gui.components import (
    Card, MetricCard, AlertItem, ProgressBar, 
    SearchBar, TabView, StatusIndicator, ConfirmDialog
)

# Notificações
try:
    from plyer import notification
    NOTIFICATIONS_AVAILABLE = True
except ImportError:
    NOTIFICATIONS_AVAILABLE = False


class LogSentinelApp(ctk.CTk):
    """Aplicação principal Log Sentinel."""
    
    def __init__(self):
        super().__init__()
        
        # Configuração da janela
        self.title(f"{Icons.OWL} Log Sentinel - Security Analysis System")
        self.geometry(f"{config.config.WINDOW_WIDTH}x{config.config.WINDOW_HEIGHT}")
        self.minsize(config.config.MIN_WIDTH, config.config.MIN_HEIGHT)
        
        # Tema
        ctk.set_appearance_mode("dark")
        self.configure(fg_color=theme.BG_PRIMARY)
        
        # Ícone (se disponível)
        try:
            icon_path = config.config.ICONS_DIR / "owl_logo.ico"
            if icon_path.exists():
                self.iconbitmap(str(icon_path))
        except:
            pass
        
        # Componentes
        self.db = DatabaseManager(str(config.config.DB_PATH))
        self.engine = DetectionEngine(self.db)
        self.exporter = ReportExporter()
        
        # Estado
        self.current_file: Optional[str] = None
        self.loaded_files: List[str] = []
        self.anomalies: List[Anomaly] = []
        self.is_analyzing = False
        self.session_id: Optional[str] = None
        
        # Callbacks de anomalias
        self.engine.on_anomaly(self._on_anomaly_detected)
        
        # Layout
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        # Criar UI
        self._create_sidebar()
        self._create_main_content()
        self._create_status_bar()
        
        # Atualizar dados
        self._update_metrics()
        
        # Timer para métricas em tempo real
        self._start_realtime_updates()
    
    # === Sidebar ===
    
    def _create_sidebar(self):
        """Cria o sidebar."""
        self.sidebar = ctk.CTkFrame(
            self,
            width=config.config.SIDEBAR_WIDTH,
            corner_radius=0,
            fg_color=theme.BG_SECONDARY,
            border_width=0
        )
        self.sidebar.grid(row=0, column=0, rowspan=2, sticky="nsew")
        self.sidebar.grid_propagate(False)
        
        # Logo section
        logo_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        logo_frame.pack(fill="x", padx=20, pady=(25, 15))
        
        # Carregar logo PNG
        self._load_sidebar_logo(logo_frame)
        
        # Title
        title_frame = ctk.CTkFrame(logo_frame, fg_color="transparent")
        title_frame.pack(pady=(10, 0))
        
        ctk.CTkLabel(
            title_frame,
            text="LOG",
            font=ctk.CTkFont(family=theme.FONT_FAMILY, size=24, weight="bold"),
            text_color=theme.ACCENT_PRIMARY
        ).pack(side="left")
        
        ctk.CTkLabel(
            title_frame,
            text="SENTINEL",
            font=ctk.CTkFont(family=theme.FONT_FAMILY, size=24, weight="bold"),
            text_color=theme.TEXT_PRIMARY
        ).pack(side="left", padx=(5, 0))
        
        # Subtitle
        ctk.CTkLabel(
            logo_frame,
            text="Security Analysis System",
            font=Fonts.small(),
            text_color=theme.TEXT_MUTED
        ).pack(pady=(5, 0))
        
        # Separator
        ctk.CTkFrame(self.sidebar, height=1, fg_color=theme.BORDER_PRIMARY).pack(fill="x", padx=20, pady=15)
        
        # Actions
        actions_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        actions_frame.pack(fill="x", padx=15)
        
        # Load file button
        self.btn_load = ctk.CTkButton(
            actions_frame,
            text=f"  {Icons.UPLOAD}  Carregar Log",
            font=Fonts.body(),
            fg_color="transparent",
            hover_color=theme.BG_HOVER,
            border_width=1,
            border_color=theme.ACCENT_PRIMARY,
            text_color=theme.ACCENT_PRIMARY,
            height=45,
            anchor="w",
            command=self._load_file
        )
        self.btn_load.pack(fill="x", pady=4)
        
        # Analyze button
        self.btn_analyze = ctk.CTkButton(
            actions_frame,
            text=f"  {Icons.SCAN}  Iniciar Análise",
            font=Fonts.body(),
            fg_color=theme.ACCENT_PRIMARY,
            hover_color=theme.ACCENT_HOVER,
            text_color=theme.TEXT_PRIMARY,
            height=45,
            anchor="w",
            command=self._start_analysis,
            state="disabled"
        )
        self.btn_analyze.pack(fill="x", pady=4)
        
        # Separator
        ctk.CTkFrame(self.sidebar, height=1, fg_color=theme.BORDER_PRIMARY).pack(fill="x", padx=20, pady=15)
        
        # Quick stats
        stats_label = ctk.CTkLabel(
            self.sidebar,
            text="  Estatísticas Rápidas",
            font=Fonts.subheading(),
            text_color=theme.TEXT_PRIMARY,
            anchor="w"
        )
        stats_label.pack(fill="x", padx=15)
        
        self.stats_frame = ctk.CTkFrame(self.sidebar, fg_color=theme.BG_TERTIARY, corner_radius=8)
        self.stats_frame.pack(fill="x", padx=15, pady=(10, 5))
        
        # Stats rows
        self.stat_labels = {}
        stats_config = [
            ("total", "Total Anomalias", theme.ACCENT_PRIMARY),
            ("critical", "Críticas", theme.CRITICAL),
            ("high", "Altas", theme.HIGH),
            ("medium", "Médias", theme.MEDIUM),
            ("low", "Baixas", theme.LOW),
        ]
        
        for key, label, color in stats_config:
            row = ctk.CTkFrame(self.stats_frame, fg_color="transparent")
            row.pack(fill="x", padx=12, pady=6)
            
            ctk.CTkLabel(
                row,
                text=label,
                font=Fonts.small(),
                text_color=theme.TEXT_SECONDARY
            ).pack(side="left")
            
            value_label = ctk.CTkLabel(
                row,
                text="0",
                font=ctk.CTkFont(family=theme.FONT_FAMILY, size=14, weight="bold"),
                text_color=color
            )
            value_label.pack(side="right")
            self.stat_labels[key] = value_label
        
        # Secondary actions
        ctk.CTkFrame(self.sidebar, height=1, fg_color=theme.BORDER_PRIMARY).pack(fill="x", padx=20, pady=15)
        
        secondary_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        secondary_frame.pack(fill="x", padx=15)
        
        # Export button
        self.btn_export = ctk.CTkButton(
            secondary_frame,
            text=f"  {Icons.EXPORT}  Exportar Relatório",
            font=Fonts.small(),
            fg_color="transparent",
            hover_color=theme.BG_HOVER,
            border_width=1,
            border_color=theme.BORDER_PRIMARY,
            text_color=theme.TEXT_SECONDARY,
            height=38,
            anchor="w",
            command=self._export_report
        )
        self.btn_export.pack(fill="x", pady=3)
        
        # Clear button
        self.btn_clear = ctk.CTkButton(
            secondary_frame,
            text=f"  {Icons.DELETE}  Limpar Dados",
            font=Fonts.small(),
            fg_color="transparent",
            hover_color=theme.BG_HOVER,
            border_width=1,
            border_color=theme.BORDER_PRIMARY,
            text_color=theme.TEXT_SECONDARY,
            height=38,
            anchor="w",
            command=self._clear_data
        )
        self.btn_clear.pack(fill="x", pady=3)
        
        # Footer
        footer = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        footer.pack(side="bottom", fill="x", padx=15, pady=15)
        
        info = get_app_info()
        ctk.CTkLabel(
            footer,
            text=f"{info['author']} (Nº {info['student_id']})\n{info['institution']}\n{info['year']}",
            font=ctk.CTkFont(size=9),
            text_color=theme.TEXT_MUTED,
            justify="center"
        ).pack()
    
    def _load_sidebar_logo(self, parent):
        """Carrega e exibe o logo PNG no sidebar."""
        # Tentar encontrar o logo
        possible_paths = [
            config.config.ICONS_DIR / "owl_logo.png",
            config.config.ICONS_DIR / "owl_logo_64.png",
            Path(__file__).parent.parent.parent / "assets" / "icons" / "owl_logo.png",
        ]
        
        logo_path = None
        for path in possible_paths:
            if path.exists():
                logo_path = path
                break
        
        if logo_path:
            try:
                img = Image.open(logo_path)
                img = img.resize((64, 64), Image.Resampling.LANCZOS)
                
                self.sidebar_logo = ctk.CTkImage(
                    light_image=img,
                    dark_image=img,
                    size=(64, 64)
                )
                
                logo_label = ctk.CTkLabel(
                    parent,
                    image=self.sidebar_logo,
                    text=""
                )
                logo_label.pack()
                return
            except Exception as e:
                print(f"Erro ao carregar logo: {e}")
        
        # Fallback: emoji
        ctk.CTkLabel(
            parent,
            text="🦉",
            font=ctk.CTkFont(size=48),
            text_color=theme.ACCENT_PRIMARY
        ).pack()
    
    # === Main Content ===
    
    def _create_main_content(self):
        """Cria o conteúdo principal."""
        self.main_frame = ctk.CTkFrame(self, fg_color=theme.BG_PRIMARY)
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=15, pady=15)
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(1, weight=1)
        
        # Header com file info
        self._create_header()
        
        # Tab view
        self.tabs = TabView(
            self.main_frame,
            tabs=["Dashboard", "Alertas", "Timeline", "Detalhes", "ML & Plugins"]
        )
        self.tabs.pack(fill="both", expand=True, pady=(10, 0))
        
        # Criar conteúdo de cada tab
        self._create_dashboard_tab()
        self._create_alerts_tab()
        self._create_timeline_tab()
        self._create_details_tab()
        self._create_ml_tab()
    
    def _create_header(self):
        """Cria o header com informações do ficheiro."""
        header = ctk.CTkFrame(self.main_frame, fg_color=theme.BG_CARD, corner_radius=8, height=60)
        header.pack(fill="x")
        header.pack_propagate(False)
        
        inner = ctk.CTkFrame(header, fg_color="transparent")
        inner.pack(fill="both", expand=True, padx=15)
        
        # Status indicator
        self.status_indicator = StatusIndicator(inner, "ready")
        self.status_indicator.pack(side="left", pady=15)
        
        # File info
        file_frame = ctk.CTkFrame(inner, fg_color="transparent")
        file_frame.pack(side="left", padx=(15, 0))
        
        self.file_label = ctk.CTkLabel(
            file_frame,
            text="Nenhum ficheiro carregado",
            font=Fonts.body(),
            text_color=theme.TEXT_PRIMARY
        )
        self.file_label.pack(anchor="w")
        
        self.file_info = ctk.CTkLabel(
            file_frame,
            text="Carregue um ficheiro de log para iniciar a análise",
            font=Fonts.small(),
            text_color=theme.TEXT_MUTED
        )
        self.file_info.pack(anchor="w")
        
        # Progress (hidden by default)
        self.progress_frame = ctk.CTkFrame(inner, fg_color="transparent")
        self.progress_frame.pack(side="right", padx=10)
        
        self.progress_label = ctk.CTkLabel(
            self.progress_frame,
            text="",
            font=Fonts.small(),
            text_color=theme.TEXT_SECONDARY
        )
        self.progress_label.pack()
        
        self.progress_bar = ctk.CTkProgressBar(
            self.progress_frame,
            width=200,
            height=6,
            fg_color=theme.BG_TERTIARY,
            progress_color=theme.ACCENT_PRIMARY
        )
        self.progress_bar.pack(pady=(5, 0))
        self.progress_bar.set(0)
        self.progress_frame.pack_forget()  # Esconder inicialmente
    
    def _create_dashboard_tab(self):
        """Cria o dashboard com layout profissional."""
        frame = self.tabs.get_tab_frame(0)
        
        # Scrollable para todo o conteúdo
        scroll = ctk.CTkScrollableFrame(frame, fg_color="transparent")
        scroll.pack(fill="both", expand=True)
        
        # === ROW 1: Metrics ===
        metrics_frame = ctk.CTkFrame(scroll, fg_color="transparent")
        metrics_frame.pack(fill="x", pady=(5, 15))
        metrics_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)
        
        self.metric_cards = {}
        
        metrics = [
            ("total", "Total Ameaças", "0", Icons.ALERT, theme.ACCENT_PRIMARY),
            ("critical", "Críticas", "0", Icons.CRITICAL, theme.CRITICAL),
            ("high", "Alta Severidade", "0", Icons.HIGH, theme.HIGH),
            ("ips", "IPs Únicos", "0", Icons.IP, theme.ACCENT_SECONDARY),
        ]
        
        for i, (key, title, value, icon, color) in enumerate(metrics):
            card = MetricCard(metrics_frame, title, value, icon, color)
            card.grid(row=0, column=i, padx=6, sticky="nsew")
            self.metric_cards[key] = card
        
        # === ROW 2: Gráfico Principal (MAIOR) + Severidades ===
        row2 = ctk.CTkFrame(scroll, fg_color="transparent")
        row2.pack(fill="both", expand=True, pady=(0, 15))
        row2.grid_columnconfigure(0, weight=3)  # Gráfico maior
        row2.grid_columnconfigure(1, weight=1)  # Severidades menor
        row2.grid_rowconfigure(0, weight=1)
        
        # Gráfico de Distribuição por Tipo (MAIOR)
        chart_card = Card(row2, "📊 Distribuição por Tipo de Ataque")
        chart_card.grid(row=0, column=0, padx=(0, 10), sticky="nsew")
        
        self.chart_canvas = ctk.CTkCanvas(
            chart_card,
            bg=theme.BG_CARD,
            highlightthickness=0,
            height=320
        )
        self.chart_canvas.pack(fill="both", expand=True, padx=15, pady=15)
        
        # Card de Severidades (à direita do gráfico)
        severity_card = Card(row2, "🎯 Por Severidade")
        severity_card.grid(row=0, column=1, sticky="nsew")
        
        self.severity_frame = ctk.CTkFrame(severity_card, fg_color="transparent")
        self.severity_frame.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        
        # Placeholder severidades
        self._create_severity_bars()
        
        # === ROW 3: Top IPs + ML Status + Últimas Ameaças ===
        row3 = ctk.CTkFrame(scroll, fg_color="transparent")
        row3.pack(fill="x", pady=(0, 10))
        row3.grid_columnconfigure((0, 1, 2), weight=1)
        row3.grid_rowconfigure(0, weight=1)
        
        # Top IPs Suspeitos
        ips_card = Card(row3, "🌐 Top IPs Suspeitos")
        ips_card.grid(row=0, column=0, padx=(0, 8), sticky="nsew")
        
        self.ips_frame = ctk.CTkScrollableFrame(
            ips_card,
            fg_color="transparent",
            height=180
        )
        self.ips_frame.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        
        # ML Status
        ml_card = Card(row3, "🤖 Machine Learning")
        ml_card.grid(row=0, column=1, padx=4, sticky="nsew")
        
        self.ml_status_frame = ctk.CTkFrame(ml_card, fg_color="transparent")
        self.ml_status_frame.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        
        self._create_ml_status_widget()
        
        # Últimas Ameaças
        recent_card = Card(row3, "⚡ Últimas Ameaças")
        recent_card.grid(row=0, column=2, padx=(8, 0), sticky="nsew")
        
        self.recent_threats_frame = ctk.CTkScrollableFrame(
            recent_card,
            fg_color="transparent",
            height=180
        )
        self.recent_threats_frame.pack(fill="both", expand=True, padx=15, pady=(0, 15))
    
    def _create_severity_bars(self):
        """Cria barras de severidade no dashboard."""
        for widget in self.severity_frame.winfo_children():
            widget.destroy()
        
        severities = [
            ("CRITICAL", theme.CRITICAL, 0),
            ("HIGH", theme.HIGH, 0),
            ("MEDIUM", theme.MEDIUM, 0),
            ("LOW", theme.LOW, 0),
        ]
        
        for name, color, count in severities:
            row = ctk.CTkFrame(self.severity_frame, fg_color="transparent")
            row.pack(fill="x", pady=8)
            
            # Label
            ctk.CTkLabel(
                row,
                text=name,
                font=Fonts.small(),
                text_color=theme.TEXT_SECONDARY,
                width=70
            ).pack(side="left")
            
            # Barra de fundo
            bar_bg = ctk.CTkFrame(row, fg_color=theme.BG_TERTIARY, height=20, corner_radius=4)
            bar_bg.pack(side="left", fill="x", expand=True, padx=(5, 10))
            
            # Barra de progresso (será atualizada)
            bar = ctk.CTkFrame(bar_bg, fg_color=color, height=20, corner_radius=4)
            bar.place(relx=0, rely=0, relwidth=0, relheight=1)
            
            # Contador
            label = ctk.CTkLabel(
                row,
                text="0",
                font=Fonts.body(),
                text_color=color,
                width=40
            )
            label.pack(side="right")
            
            # Guardar referências
            if not hasattr(self, 'severity_bars'):
                self.severity_bars = {}
            self.severity_bars[name] = {'bar': bar, 'label': label, 'bg': bar_bg}
    
    def _create_ml_status_widget(self):
        """Cria widget de status ML no dashboard."""
        for widget in self.ml_status_frame.winfo_children():
            widget.destroy()
        
        # Status icon
        status_frame = ctk.CTkFrame(self.ml_status_frame, fg_color=theme.BG_TERTIARY, corner_radius=8)
        status_frame.pack(fill="x", pady=(5, 10))
        
        self.ml_status_label = ctk.CTkLabel(
            status_frame,
            text="⏳ A aguardar análise",
            font=Fonts.body(),
            text_color=theme.WARNING
        )
        self.ml_status_label.pack(pady=12)
        
        # Stats
        stats_frame = ctk.CTkFrame(self.ml_status_frame, fg_color="transparent")
        stats_frame.pack(fill="x")
        
        self.ml_stats = {}
        
        for label, key in [("Amostras", "samples"), ("Anomalias ML", "ml_anomalies")]:
            row = ctk.CTkFrame(stats_frame, fg_color="transparent")
            row.pack(fill="x", pady=3)
            
            ctk.CTkLabel(
                row,
                text=label,
                font=Fonts.small(),
                text_color=theme.TEXT_MUTED
            ).pack(side="left")
            
            val_label = ctk.CTkLabel(
                row,
                text="—",
                font=Fonts.body(),
                text_color=theme.TEXT_PRIMARY
            )
            val_label.pack(side="right")
            self.ml_stats[key] = val_label
        
        # Features info
        ctk.CTkLabel(
            self.ml_status_frame,
            text="Isolation Forest\n20 features • Auto-treino",
            font=Fonts.small(),
            text_color=theme.TEXT_MUTED,
            justify="center"
        ).pack(pady=(15, 5))
    
    def _update_dashboard_severity_bars(self):
        """Atualiza as barras de severidade no dashboard."""
        if not hasattr(self, 'severity_bars'):
            return
        
        stats = self.engine.get_stats()
        by_severity = stats.get('by_severity', {})
        total = sum(by_severity.values()) if by_severity else 1
        
        for name, widgets in self.severity_bars.items():
            count = by_severity.get(name, 0)
            percentage = count / total if total > 0 else 0
            
            widgets['bar'].place(relx=0, rely=0, relwidth=max(0.02, percentage), relheight=1)
            widgets['label'].configure(text=str(count))
    
    def _update_dashboard_ml_status(self):
        """Atualiza status ML no dashboard."""
        if not hasattr(self, 'ml_status_label'):
            return
        
        stats = self.engine.get_stats()
        is_trained = stats.get('ml_trained', False)
        
        if is_trained:
            self.ml_status_label.configure(
                text="✅ Modelo Treinado",
                text_color=theme.SUCCESS
            )
        else:
            self.ml_status_label.configure(
                text="⏳ A aguardar análise",
                text_color=theme.WARNING
            )
        
        # Atualizar stats
        if hasattr(self, 'ml_stats'):
            self.ml_stats['samples'].configure(text=str(stats.get('entries_processed', 0)))
            self.ml_stats['ml_anomalies'].configure(text=str(stats.get('ml_detections', 0)))
    
    def _update_dashboard_recent_threats(self):
        """Atualiza lista de últimas ameaças."""
        if not hasattr(self, 'recent_threats_frame'):
            return
        
        for widget in self.recent_threats_frame.winfo_children():
            widget.destroy()
        
        if not self.anomalies:
            ctk.CTkLabel(
                self.recent_threats_frame,
                text="Nenhuma ameaça",
                font=Fonts.small(),
                text_color=theme.TEXT_MUTED
            ).pack(pady=20)
            return
        
        # Mostrar últimas 5 ameaças críticas/altas
        critical_threats = [a for a in self.anomalies if a.severity.value in ['CRITICAL', 'HIGH']][:5]
        
        if not critical_threats:
            critical_threats = self.anomalies[:5]
        
        for anomaly in critical_threats:
            row = ctk.CTkFrame(self.recent_threats_frame, fg_color=theme.BG_TERTIARY, corner_radius=4)
            row.pack(fill="x", pady=2)
            
            severity_colors = {
                'CRITICAL': theme.CRITICAL,
                'HIGH': theme.HIGH,
                'MEDIUM': theme.MEDIUM,
                'LOW': theme.LOW
            }
            color = severity_colors.get(anomaly.severity.value, theme.TEXT_MUTED)
            
            # Indicador de cor
            indicator = ctk.CTkFrame(row, fg_color=color, width=4, corner_radius=2)
            indicator.pack(side="left", fill="y", padx=(0, 8))
            
            # Info
            info = ctk.CTkFrame(row, fg_color="transparent")
            info.pack(side="left", fill="x", expand=True, pady=6, padx=(0, 8))
            
            ctk.CTkLabel(
                info,
                text=anomaly.anomaly_type.value.replace('_', ' ').title()[:20],
                font=Fonts.small(),
                text_color=theme.TEXT_PRIMARY
            ).pack(anchor="w")
            
            ctk.CTkLabel(
                info,
                text=anomaly.source_ip or "N/A",
                font=ctk.CTkFont(family="Consolas", size=10),
                text_color=theme.TEXT_MUTED
            ).pack(anchor="w")
    
    def _create_alerts_tab(self):
        """Cria a tab de alertas."""
        frame = self.tabs.get_tab_frame(1)
        
        # Header com filtros
        header = ctk.CTkFrame(frame, fg_color="transparent")
        header.pack(fill="x", pady=(0, 10))
        
        # Search
        self.alerts_search = SearchBar(header, "Pesquisar alertas...", self._filter_alerts)
        self.alerts_search.pack(side="left", fill="x", expand=True)
        
        # Filter dropdown
        self.severity_filter = ctk.CTkOptionMenu(
            header,
            values=["Todas", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
            font=Fonts.small(),
            fg_color=theme.BG_TERTIARY,
            button_color=theme.BG_HOVER,
            dropdown_fg_color=theme.BG_CARD,
            command=self._filter_alerts
        )
        self.severity_filter.pack(side="right", padx=(10, 0))
        
        # Alerts list
        self.alerts_list = ctk.CTkScrollableFrame(
            frame,
            fg_color="transparent"
        )
        self.alerts_list.pack(fill="both", expand=True)
        
        # Empty state
        self._show_empty_alerts()
    
    def _create_timeline_tab(self):
        """Cria a tab de timeline com filtros e gráfico expandido."""
        frame = self.tabs.get_tab_frame(2)
        
        # Header com filtros
        header = ctk.CTkFrame(frame, fg_color="transparent")
        header.pack(fill="x", pady=(0, 15))
        
        # Título
        ctk.CTkLabel(
            header,
            text="📈 Timeline de Anomalias",
            font=Fonts.heading(),
            text_color=theme.TEXT_PRIMARY
        ).pack(side="left")
        
        # Filtros à direita
        filters_frame = ctk.CTkFrame(header, fg_color="transparent")
        filters_frame.pack(side="right")
        
        ctk.CTkLabel(
            filters_frame,
            text="Período:",
            font=Fonts.small(),
            text_color=theme.TEXT_MUTED
        ).pack(side="left", padx=(0, 8))
        
        self.timeline_period = ctk.CTkOptionMenu(
            filters_frame,
            values=["Todas as horas", "Últimas 6h", "Últimas 12h", "Horário trabalho (8h-18h)", "Fora de horário"],
            font=Fonts.small(),
            width=180,
            fg_color=theme.BG_TERTIARY,
            button_color=theme.BG_HOVER,
            dropdown_fg_color=theme.BG_CARD,
            command=self._filter_timeline
        )
        self.timeline_period.pack(side="left", padx=(0, 15))
        
        ctk.CTkLabel(
            filters_frame,
            text="Agrupar:",
            font=Fonts.small(),
            text_color=theme.TEXT_MUTED
        ).pack(side="left", padx=(0, 8))
        
        self.timeline_group = ctk.CTkOptionMenu(
            filters_frame,
            values=["Por hora", "Por 30 min", "Por 15 min"],
            font=Fonts.small(),
            width=120,
            fg_color=theme.BG_TERTIARY,
            button_color=theme.BG_HOVER,
            dropdown_fg_color=theme.BG_CARD,
            command=self._filter_timeline
        )
        self.timeline_group.pack(side="left")
        
        # Container principal para o gráfico (ocupa todo o espaço)
        chart_container = ctk.CTkFrame(frame, fg_color=theme.BG_CARD, corner_radius=10)
        chart_container.pack(fill="both", expand=True)
        
        # Timeline canvas - MAIOR
        self.timeline_canvas = ctk.CTkCanvas(
            chart_container,
            bg=theme.BG_CARD,
            highlightthickness=0
        )
        self.timeline_canvas.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Bind resize para redesenhar
        self.timeline_canvas.bind("<Configure>", lambda e: self._draw_timeline_on_resize())
        
        # Placeholder
        self.timeline_canvas.create_text(
            400, 200,
            text="Timeline será exibida após análise",
            fill=theme.TEXT_MUTED,
            font=(theme.FONT_FAMILY, 14)
        )
        
        # Info footer
        self.timeline_info = ctk.CTkLabel(
            frame,
            text="",
            font=Fonts.small(),
            text_color=theme.TEXT_MUTED
        )
        self.timeline_info.pack(pady=(10, 0))
    
    def _filter_timeline(self, *args):
        """Aplica filtros à timeline."""
        self._update_timeline()
    
    def _draw_timeline_on_resize(self):
        """Redesenha timeline quando janela redimensiona."""
        if hasattr(self, 'anomalies') and self.anomalies:
            self.after(100, self._update_timeline)
    
    def _create_details_tab(self):
        """Cria a tab de detalhes com layout melhorado."""
        frame = self.tabs.get_tab_frame(3)
        
        # Layout em 2 colunas
        frame.grid_columnconfigure(0, weight=2)
        frame.grid_columnconfigure(1, weight=1)
        frame.grid_rowconfigure(0, weight=1)
        
        # Coluna esquerda - Relatório textual
        left_frame = ctk.CTkFrame(frame, fg_color="transparent")
        left_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        
        ctk.CTkLabel(
            left_frame,
            text="📋 Relatório de Análise",
            font=Fonts.subheading(),
            text_color=theme.TEXT_PRIMARY
        ).pack(anchor="w", pady=(0, 10))
        
        self.details_text = ctk.CTkTextbox(
            left_frame,
            font=Fonts.mono(),
            fg_color=theme.BG_CARD,
            text_color=theme.TEXT_PRIMARY,
            corner_radius=8
        )
        self.details_text.pack(fill="both", expand=True)
        
        # Coluna direita - Resumo rápido
        right_frame = ctk.CTkFrame(frame, fg_color="transparent")
        right_frame.grid(row=0, column=1, sticky="nsew")
        
        ctk.CTkLabel(
            right_frame,
            text="⚡ Resumo Rápido",
            font=Fonts.subheading(),
            text_color=theme.TEXT_PRIMARY
        ).pack(anchor="w", pady=(0, 10))
        
        # Cards de resumo
        self.summary_frame = ctk.CTkScrollableFrame(
            right_frame,
            fg_color=theme.BG_CARD,
            corner_radius=8
        )
        self.summary_frame.pack(fill="both", expand=True)
        
        self._show_welcome_message()
    
    def _create_ml_tab(self):
        """Cria a tab de ML e Plugins."""
        frame = self.tabs.get_tab_frame(4)
        self._create_ml_tab_content(frame)
    
    def _on_plugin_toggle(self, plugin_name):
        """Callback quando um plugin é ativado/desativado."""
        switch = self.plugin_switches.get(plugin_name)
        if switch:
            status = "ativado" if switch.get() else "desativado"
            self._set_status(f"Plugin {plugin_name.split(' ', 1)[1]} {status}")
    
    def _update_ml_tab(self):
        """Atualiza a tab ML & Plugins após análise."""
        # Reconstruir a tab para mostrar novos dados
        frame = self.tabs.get_tab_frame(4)
        
        # Limpar conteúdo existente
        for widget in frame.winfo_children():
            widget.destroy()
        
        # Reconstruir
        self._create_ml_tab_content(frame)
    
    def _create_ml_tab_content(self, frame):
        """Cria o conteúdo da tab ML & Plugins."""
        # Scrollable frame
        scroll = ctk.CTkScrollableFrame(frame, fg_color="transparent")
        scroll.pack(fill="both", expand=True)
        
        # Obter estatísticas atualizadas
        stats = self.engine.get_stats()
        
        # === ML Section ===
        ml_card = Card(scroll, "🤖 Machine Learning - Deteção Inteligente")
        ml_card.pack(fill="x", pady=(0, 15))
        
        ml_content = ctk.CTkFrame(ml_card, fg_color="transparent")
        ml_content.pack(fill="x", padx=16, pady=(0, 16))
        
        # Explicação
        ctk.CTkLabel(
            ml_content,
            text="O sistema utiliza Isolation Forest para detetar anomalias automaticamente.\n"
                 "Quanto mais logs analisar, mais inteligente o sistema fica!",
            font=Fonts.body(),
            text_color=theme.TEXT_SECONDARY,
            justify="left"
        ).pack(anchor="w", pady=(0, 15))
        
        # Status box
        status_frame = ctk.CTkFrame(ml_content, fg_color=theme.BG_TERTIARY, corner_radius=8)
        status_frame.pack(fill="x", pady=(0, 10))
        
        status_inner = ctk.CTkFrame(status_frame, fg_color="transparent")
        status_inner.pack(fill="x", padx=15, pady=12)
        
        # Status indicator - usar get_stats atualizado
        is_trained = stats.get('ml_trained', False)
        ml_detections = stats.get('ml_detections', 0)
        
        if is_trained:
            status_text = "✅ Modelo Treinado"
            status_color = theme.SUCCESS
        else:
            status_text = "⏳ A aguardar dados (mínimo 20 linhas)"
            status_color = theme.WARNING
        
        ctk.CTkLabel(
            status_inner,
            text=status_text,
            font=ctk.CTkFont(family=theme.FONT_FAMILY, size=14, weight="bold"),
            text_color=status_color
        ).pack(anchor="w")
        
        ctk.CTkLabel(
            status_inner,
            text=f"Deteções ML: {ml_detections} anomalias identificadas por IA",
            font=Fonts.small(),
            text_color=theme.TEXT_MUTED
        ).pack(anchor="w", pady=(5, 0))
        
        # Como funciona
        how_frame = ctk.CTkFrame(ml_content, fg_color=theme.BG_TERTIARY, corner_radius=8)
        how_frame.pack(fill="x", pady=(10, 0))
        
        how_inner = ctk.CTkFrame(how_frame, fg_color="transparent")
        how_inner.pack(fill="x", padx=15, pady=12)
        
        ctk.CTkLabel(
            how_inner,
            text="📊 Como funciona:",
            font=Fonts.subheading(),
            text_color=theme.TEXT_PRIMARY
        ).pack(anchor="w")
        
        steps = [
            "1. O sistema extrai 20 características de cada linha de log",
            "2. Isolation Forest identifica padrões anormais",
            "3. Anomalias são sinalizadas mesmo sem padrões conhecidos",
            "4. O modelo melhora com mais dados analisados"
        ]
        
        for step in steps:
            ctk.CTkLabel(
                how_inner,
                text=step,
                font=Fonts.small(),
                text_color=theme.TEXT_SECONDARY
            ).pack(anchor="w", pady=2)
        
        # === Plugins Section ===
        plugins_card = Card(scroll, "🔌 Plugins de Deteção Ativa")
        plugins_card.pack(fill="x", pady=(0, 15))
        
        plugins_content = ctk.CTkFrame(plugins_card, fg_color="transparent")
        plugins_content.pack(fill="x", padx=16, pady=(0, 16))
        
        ctk.CTkLabel(
            plugins_content,
            text="Plugins adicionam capacidades de deteção especializadas.\n"
                 "Ative/desative conforme necessário para a sua análise.",
            font=Fonts.body(),
            text_color=theme.TEXT_SECONDARY,
            justify="left"
        ).pack(anchor="w", pady=(0, 15))
        
        plugins_info = [
            ("🔥 API Abuse Detector", 
             "Deteta quando um IP faz demasiados pedidos a endpoints /api/\nÚtil para identificar bots e scrapers", 
             True),
            ("🔐 Sensitive Data Detector", 
             "Encontra exposição de passwords, API keys e tokens em URLs\nCrítico para segurança de dados", 
             True),
            ("🌙 Anomalous Time Detector", 
             "Identifica atividade fora do horário normal (20h-8h)\nÚtil para detetar intrusões noturnas", 
             True),
        ]
        
        self.plugin_switches = {}
        
        for name, desc, enabled in plugins_info:
            plugin_row = ctk.CTkFrame(plugins_content, fg_color=theme.BG_TERTIARY, corner_radius=8)
            plugin_row.pack(fill="x", pady=5)
            
            info = ctk.CTkFrame(plugin_row, fg_color="transparent")
            info.pack(side="left", fill="x", expand=True, padx=15, pady=12)
            
            ctk.CTkLabel(
                info,
                text=name,
                font=Fonts.subheading(),
                text_color=theme.TEXT_PRIMARY
            ).pack(anchor="w")
            
            ctk.CTkLabel(
                info,
                text=desc,
                font=Fonts.small(),
                text_color=theme.TEXT_MUTED,
                justify="left"
            ).pack(anchor="w", pady=(3, 0))
            
            switch = ctk.CTkSwitch(
                plugin_row,
                text="Ativo" if enabled else "Inativo",
                font=Fonts.small(),
                onvalue=True,
                offvalue=False,
                command=lambda n=name: self._on_plugin_toggle(n)
            )
            switch.pack(side="right", padx=15)
            if enabled:
                switch.select()
            self.plugin_switches[name] = switch
        
        # === Estatísticas de Deteção ===
        stats_card = Card(scroll, "📈 Resumo de Deteções")
        stats_card.pack(fill="x")
        
        stats_content = ctk.CTkFrame(stats_card, fg_color="transparent")
        stats_content.pack(fill="x", padx=16, pady=(0, 16))
        
        pattern_detections = stats.get('anomalies_detected', 0) - ml_detections
        
        detection_stats = [
            ("Total de anomalias", str(stats.get('anomalies_detected', 0)), theme.ACCENT_PRIMARY),
            ("Por padrões (regex)", str(pattern_detections), theme.HIGH),
            ("Por Machine Learning", str(ml_detections), theme.SUCCESS),
        ]
        
        stats_grid = ctk.CTkFrame(stats_content, fg_color="transparent")
        stats_grid.pack(fill="x")
        
        for i, (label, value, color) in enumerate(detection_stats):
            stat_box = ctk.CTkFrame(stats_grid, fg_color=theme.BG_TERTIARY, corner_radius=8)
            stat_box.pack(side="left", fill="x", expand=True, padx=(0 if i == 0 else 5, 0))
            
            stat_inner = ctk.CTkFrame(stat_box, fg_color="transparent")
            stat_inner.pack(padx=15, pady=12)
            
            ctk.CTkLabel(
                stat_inner,
                text=value,
                font=ctk.CTkFont(family=theme.FONT_FAMILY, size=24, weight="bold"),
                text_color=color
            ).pack()
            
            ctk.CTkLabel(
                stat_inner,
                text=label,
                font=Fonts.small(),
                text_color=theme.TEXT_MUTED
            ).pack()
    
    # === Status Bar ===
    
    def _create_status_bar(self):
        """Cria a barra de status."""
        self.status_bar = ctk.CTkFrame(
            self,
            height=30,
            fg_color=theme.BG_SECONDARY,
            corner_radius=0
        )
        self.status_bar.grid(row=1, column=1, sticky="ew", padx=15, pady=(0, 10))
        
        self.status_text = ctk.CTkLabel(
            self.status_bar,
            text=f"{Icons.SUCCESS} Sistema pronto",
            font=Fonts.small(),
            text_color=theme.TEXT_MUTED
        )
        self.status_text.pack(side="left", padx=10, pady=5)
        
        # Version
        info = get_app_info()
        ctk.CTkLabel(
            self.status_bar,
            text=f"v{info['version']}",
            font=Fonts.small(),
            text_color=theme.TEXT_MUTED
        ).pack(side="right", padx=10)
    
    # === Actions ===
    
    def _load_file(self):
        """Carrega ficheiro(s) de log."""
        filetypes = [
            ("Log Files", "*.log *.txt"),
            ("All Files", "*.*")
        ]
        # Permitir selecionar múltiplos ficheiros
        filepaths = filedialog.askopenfilenames(filetypes=filetypes)
        
        if filepaths:
            # Converter para lista
            self.loaded_files = list(filepaths)
            
            if len(self.loaded_files) == 1:
                # Um ficheiro
                self.current_file = self.loaded_files[0]
                filename = os.path.basename(self.current_file)
                filesize = os.path.getsize(self.current_file)
                self.file_label.configure(text=filename)
                self.file_info.configure(text=f"{filesize:,} bytes | Pronto para análise")
            else:
                # Múltiplos ficheiros
                self.current_file = self.loaded_files[0]  # Primeiro para referência
                total_size = sum(os.path.getsize(f) for f in self.loaded_files)
                filenames = [os.path.basename(f) for f in self.loaded_files]
                self.file_label.configure(text=f"{len(self.loaded_files)} ficheiros selecionados")
                self.file_info.configure(text=f"{total_size:,} bytes total | {', '.join(filenames[:3])}{'...' if len(filenames) > 3 else ''}")
            
            # Guardar no histórico
            self._save_to_history(self.loaded_files)
            
            self.btn_analyze.configure(state="normal")
            self.status_indicator.set_status("ready")
            
            self._set_status(f"{Icons.SUCCESS} {len(self.loaded_files)} ficheiro(s) carregado(s)")
    
    def _save_to_history(self, filepaths):
        """Guarda ficheiros no histórico."""
        try:
            history_file = config.config.DATA_DIR / "log_history.json"
            
            # Carregar histórico existente
            history = []
            if history_file.exists():
                with open(history_file, 'r') as f:
                    history = json.load(f)
            
            # Adicionar novos ficheiros
            for filepath in filepaths:
                entry = {
                    'path': filepath,
                    'name': os.path.basename(filepath),
                    'size': os.path.getsize(filepath),
                    'loaded_at': datetime.now().isoformat()
                }
                # Remover duplicados
                history = [h for h in history if h['path'] != filepath]
                history.insert(0, entry)
            
            # Manter apenas os últimos 20
            history = history[:20]
            
            # Guardar
            with open(history_file, 'w') as f:
                json.dump(history, f, indent=2)
                
        except Exception as e:
            print(f"Erro ao guardar histórico: {e}")
    
    def _load_history(self):
        """Carrega histórico de ficheiros."""
        try:
            history_file = config.config.DATA_DIR / "log_history.json"
            if history_file.exists():
                with open(history_file, 'r') as f:
                    return json.load(f)
        except:
            pass
        return []
    
    def _start_analysis(self):
        """Inicia análise em thread separada."""
        if not hasattr(self, 'loaded_files') or not self.loaded_files:
            if not self.current_file:
                return
            self.loaded_files = [self.current_file]
        
        if self.is_analyzing:
            return
        
        self.is_analyzing = True
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # UI updates
        self.btn_analyze.configure(state="disabled", text=f"  {Icons.SCAN}  A analisar...")
        self.status_indicator.set_status("scanning")
        self.progress_frame.pack(side="right", padx=10)
        self.progress_bar.set(0)
        
        # Start thread
        thread = threading.Thread(target=self._run_analysis, daemon=True)
        thread.start()
    
    def _run_analysis(self):
        """Executa análise de múltiplos ficheiros (em thread)."""
        try:
            self.engine.reset()
            all_anomalies = []
            
            total_files = len(self.loaded_files)
            
            for file_idx, filepath in enumerate(self.loaded_files):
                # Atualizar status
                filename = os.path.basename(filepath)
                self.after(0, lambda f=filename, i=file_idx: self._set_status(
                    f"{Icons.SCAN} A analisar {f} ({i+1}/{total_files})..."
                ))
                
                def on_progress(current, total):
                    # Progresso combinado: ficheiro atual + posição no total de ficheiros
                    file_progress = current / total if total > 0 else 0
                    overall_progress = (file_idx + file_progress) / total_files
                    self.after(0, lambda p=overall_progress, c=current, t=total: 
                        self._update_progress(p, c, t))
                
                file_anomalies = self.engine.analyze_file(
                    filepath,
                    self.session_id,
                    progress_callback=on_progress
                )
                all_anomalies.extend(file_anomalies)
            
            self.anomalies = all_anomalies
            
            # Correlacionar
            self.engine.correlate_anomalies()
            
            self.after(0, self._analysis_complete)
            
        except Exception as e:
            import traceback
            traceback.print_exc()
            self.after(0, lambda: self._analysis_error(str(e)))
    
    def _update_progress(self, progress: float, current: int, total: int):
        """Atualiza progresso."""
        self.progress_bar.set(progress)
        self.progress_label.configure(text=f"{current:,} / {total:,} linhas")
    
    def _analysis_complete(self):
        """Callback quando análise termina."""
        self.is_analyzing = False
        stats = self.engine.get_stats()
        
        # UI updates
        self.btn_analyze.configure(state="normal", text=f"  {Icons.SCAN}  Iniciar Análise")
        self.status_indicator.set_status("online")
        self.progress_frame.pack_forget()
        
        # Info baseada em número de ficheiros
        num_files = len(self.loaded_files) if self.loaded_files else 1
        if num_files > 1:
            self.file_info.configure(
                text=f"{num_files} ficheiros | {stats['entries_processed']:,} linhas | {stats['anomalies_detected']} ameaças"
            )
        else:
            self.file_info.configure(
                text=f"{stats['entries_processed']:,} linhas | {stats['anomalies_detected']} ameaças detetadas"
            )
        
        self._set_status(f"{Icons.SUCCESS} Análise concluída: {stats['anomalies_detected']} anomalias encontradas")
        
        # Atualizar UI
        self._update_metrics()
        self._update_alerts()
        self._update_dashboard()
        self._update_details()
        self._update_timeline()
        self._update_ml_tab()
        
        # Notificação desktop
        if stats['anomalies_detected'] > 0:
            self._send_notification(
                "Análise Concluída",
                f"{stats['anomalies_detected']} ameaças detetadas"
            )
        
        # Popup
        files_text = f"Ficheiros analisados: {num_files}\n" if num_files > 1 else ""
        messagebox.showinfo(
            "Análise Concluída",
            f"{files_text}"
            f"Linhas processadas: {stats['entries_processed']:,}\n"
            f"Anomalias detetadas: {stats['anomalies_detected']}\n"
            f"Críticas: {stats['by_severity'].get('CRITICAL', 0)}\n"
            f"ML deteções: {stats.get('ml_detections', 0)}"
        )
    
    def _analysis_error(self, error: str):
        """Callback quando análise falha."""
        self.is_analyzing = False
        self.btn_analyze.configure(state="normal", text=f"  {Icons.SCAN}  Iniciar Análise")
        self.status_indicator.set_status("error")
        self.progress_frame.pack_forget()
        
        self._set_status(f"{Icons.ERROR} Erro: {error}")
        messagebox.showerror("Erro", f"Erro durante análise:\n{error}")
    
    def _on_anomaly_detected(self, anomaly: Anomaly):
        """Callback para cada anomalia detetada."""
        # Notificar para críticas
        if anomaly.severity == Severity.CRITICAL:
            self._send_notification(
                f"⚠️ {anomaly.anomaly_type.value}",
                anomaly.detail[:100]
            )
    
    def _export_report(self):
        """Exporta relatório."""
        if not self.anomalies:
            messagebox.showwarning("Aviso", "Nenhuma anomalia para exportar")
            return
        
        filetypes = [
            ("PDF", "*.pdf"),
            ("CSV", "*.csv"),
            ("JSON", "*.json"),
            ("Word", "*.docx"),
        ]
        
        filepath = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            filetypes=filetypes
        )
        
        if filepath:
            try:
                ext = os.path.splitext(filepath)[1][1:]
                anomaly_dicts = [a.to_dict() for a in self.anomalies]
                stats = self.engine.get_stats()
                stats['total_anomalies'] = stats['anomalies_detected']
                stats['top_ips'] = self.db.get_statistics()['top_ips']
                
                self.exporter.export(anomaly_dicts, stats, filepath, ext)
                
                self._set_status(f"{Icons.SUCCESS} Relatório exportado: {os.path.basename(filepath)}")
                messagebox.showinfo("Sucesso", f"Relatório guardado em:\n{filepath}")
                
            except Exception as e:
                messagebox.showerror("Erro", f"Erro ao exportar:\n{e}")
    
    def _clear_data(self):
        """Limpa todos os dados."""
        if messagebox.askyesno("Confirmar", "Limpar todos os dados?"):
            self.db.clear_anomalies()
            self.engine.reset()
            self.anomalies = []
            self.current_file = None
            
            self.file_label.configure(text="Nenhum ficheiro carregado")
            self.file_info.configure(text="Carregue um ficheiro de log para iniciar a análise")
            self.btn_analyze.configure(state="disabled")
            
            self._update_metrics()
            self._update_alerts()
            self._update_dashboard()
            self._show_welcome_message()
            
            self._set_status(f"{Icons.SUCCESS} Dados limpos")
    
    # === UI Updates ===
    
    def _update_metrics(self):
        """Atualiza métricas."""
        stats = self.db.get_statistics()
        
        self.stat_labels['total'].configure(text=str(stats['total_anomalies']))
        self.stat_labels['critical'].configure(text=str(stats['by_severity'].get('CRITICAL', 0)))
        self.stat_labels['high'].configure(text=str(stats['by_severity'].get('HIGH', 0)))
        self.stat_labels['medium'].configure(text=str(stats['by_severity'].get('MEDIUM', 0)))
        self.stat_labels['low'].configure(text=str(stats['by_severity'].get('LOW', 0)))
        
        # Metric cards
        if hasattr(self, 'metric_cards'):
            self.metric_cards['total'].set_value(str(stats['total_anomalies']))
            self.metric_cards['critical'].set_value(str(stats['by_severity'].get('CRITICAL', 0)))
            self.metric_cards['high'].set_value(str(stats['by_severity'].get('HIGH', 0)))
            self.metric_cards['ips'].set_value(str(len(stats['top_ips'])))
    
    def _update_alerts(self):
        """Atualiza lista de alertas com filtros."""
        # Limpar
        for widget in self.alerts_list.winfo_children():
            widget.destroy()
        
        if not self.anomalies:
            self._show_empty_alerts()
            return
        
        # Obter filtros
        search_text = self.alerts_search.get().lower() if hasattr(self, 'alerts_search') else ""
        severity_filter = self.severity_filter.get() if hasattr(self, 'severity_filter') else "Todas"
        
        # Filtrar anomalias
        filtered = []
        for anomaly in self.anomalies:
            # Filtro de severidade
            if severity_filter != "Todas" and anomaly.severity.value != severity_filter:
                continue
            
            # Filtro de pesquisa
            if search_text:
                searchable = f"{anomaly.anomaly_type.value} {anomaly.detail} {anomaly.source_ip or ''}".lower()
                if search_text not in searchable:
                    continue
            
            filtered.append(anomaly)
        
        if not filtered:
            ctk.CTkLabel(
                self.alerts_list,
                text=f"Nenhum resultado para os filtros aplicados",
                font=Fonts.body(),
                text_color=theme.TEXT_MUTED
            ).pack(pady=50)
            return
        
        # Mostrar contador
        count_label = ctk.CTkLabel(
            self.alerts_list,
            text=f"A mostrar {len(filtered)} de {len(self.anomalies)} alertas",
            font=Fonts.small(),
            text_color=theme.TEXT_MUTED
        )
        count_label.pack(pady=(0, 10))
        
        for anomaly in filtered[:100]:
            item = AlertItem(
                self.alerts_list,
                anomaly_type=anomaly.anomaly_type.value,
                severity=anomaly.severity.value,
                detail=anomaly.detail,
                source_ip=anomaly.source_ip,
                timestamp=anomaly.timestamp.strftime("%H:%M:%S") if anomaly.timestamp else None
            )
            item.pack(fill="x", pady=3)
    
    def _show_empty_alerts(self):
        """Mostra estado vazio."""
        empty = ctk.CTkLabel(
            self.alerts_list,
            text="Nenhuma anomalia detetada",
            font=Fonts.body(),
            text_color=theme.TEXT_MUTED
        )
        empty.pack(pady=50)
    
    def _update_dashboard(self):
        """Atualiza dashboard completo."""
        stats = self.db.get_statistics()
        
        # Desenhar gráfico
        self._draw_chart(stats['by_type'])
        
        # Atualizar top IPs
        for widget in self.ips_frame.winfo_children():
            widget.destroy()
        
        if not stats['top_ips']:
            ctk.CTkLabel(
                self.ips_frame,
                text="Nenhum IP",
                font=Fonts.small(),
                text_color=theme.TEXT_MUTED
            ).pack(pady=20)
        else:
            for ip, count in stats['top_ips'][:8]:
                row = ctk.CTkFrame(self.ips_frame, fg_color=theme.BG_TERTIARY, corner_radius=4)
                row.pack(fill="x", pady=2)
                
                ctk.CTkLabel(
                    row,
                    text=ip,
                    font=Fonts.mono_small(),
                    text_color=theme.TEXT_PRIMARY
                ).pack(side="left", padx=10, pady=6)
                
                ctk.CTkLabel(
                    row,
                    text=str(count),
                    font=Fonts.body(),
                    text_color=theme.ACCENT_PRIMARY
                ).pack(side="right", padx=10, pady=6)
        
        # Atualizar barras de severidade
        self._update_dashboard_severity_bars()
        
        # Atualizar status ML
        self._update_dashboard_ml_status()
        
        # Atualizar últimas ameaças
        self._update_dashboard_recent_threats()
    
    def _draw_chart(self, by_type: Dict[str, int]):
        """Desenha gráfico de barras horizontal."""
        self.chart_canvas.delete("all")
        
        if not by_type:
            self.chart_canvas.create_text(
                200, 150,
                text="Sem dados",
                fill=theme.TEXT_MUTED,
                font=(theme.FONT_FAMILY, 12)
            )
            return
        
        # Configurações - aumentar margem para nomes longos
        margin_left = 160  # Mais espaço para labels
        margin_right = 60
        margin_top = 30
        bar_height = 28
        spacing = 8
        max_value = max(by_type.values()) if by_type else 1
        
        canvas_width = self.chart_canvas.winfo_width() or 500
        canvas_height = self.chart_canvas.winfo_height() or 400
        max_bar_width = canvas_width - margin_left - margin_right
        
        colors = list(theme.CHART_COLORS)
        
        # Limitar a 10 tipos
        sorted_types = sorted(by_type.items(), key=lambda x: -x[1])[:10]
        
        for i, (attack_type, count) in enumerate(sorted_types):
            y = margin_top + i * (bar_height + spacing)
            
            # Formatar nome - substituir _ por espaço e abreviar se necessário
            display_name = attack_type.replace('_', ' ').title()
            if len(display_name) > 18:
                display_name = display_name[:16] + '...'
            
            # Label à esquerda
            self.chart_canvas.create_text(
                margin_left - 10, y + bar_height / 2,
                text=display_name,
                fill=theme.TEXT_SECONDARY,
                font=(theme.FONT_FAMILY, 10),
                anchor="e"  # Alinhar à direita
            )
            
            # Barra
            bar_width = (count / max_value) * max_bar_width if max_value > 0 else 0
            color = colors[i % len(colors)]
            
            # Barra com cantos arredondados (simulado com retângulo)
            self.chart_canvas.create_rectangle(
                margin_left, y + 2,
                margin_left + max(bar_width, 5), y + bar_height - 2,
                fill=color,
                outline=""
            )
            
            # Valor no fim da barra
            self.chart_canvas.create_text(
                margin_left + bar_width + 8, y + bar_height / 2,
                text=str(count),
                fill=theme.TEXT_PRIMARY,
                font=(theme.FONT_FAMILY, 11, "bold"),
                anchor="w"
            )
    
    def _update_details(self):
        """Atualiza detalhes e resumo rápido."""
        self.details_text.configure(state="normal")
        self.details_text.delete("1.0", "end")
        
        stats = self.engine.get_stats()
        
        text = f"""
╔══════════════════════════════════════════════════════════════╗
║                    LOG SENTINEL - RELATÓRIO                  ║
╚══════════════════════════════════════════════════════════════╝

  Ficheiro: {self.current_file or 'N/A'}
  Data: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}

  ─────────────────────────────────────────────────────────────

  ESTATÍSTICAS:
  
    Linhas processadas: {stats['entries_processed']:,}
    Anomalias detetadas: {stats['anomalies_detected']}
    Deteções ML: {stats['ml_detections']}

  SEVERIDADE:

"""
        for sev, count in stats['by_severity'].items():
            bar = '█' * min(count, 30)
            text += f"    [{sev:10}] {bar} {count}\n"
        
        text += "\n  TIPOS DE ATAQUE:\n\n"
        for t, count in sorted(stats['by_type'].items(), key=lambda x: -x[1]):
            text += f"    • {t}: {count}\n"
        
        text += "\n  ANOMALIAS RECENTES:\n\n"
        for i, a in enumerate(self.anomalies[:20], 1):
            text += f"    [{i:02}] {a.anomaly_type.value} [{a.severity.value}] {a.source_ip or 'N/A'}\n"
            text += f"         {a.detail[:60]}...\n\n"
        
        text += "\n  ─────────────────────────────────────────────────────────────\n"
        text += f"  Log Sentinel v{get_app_info()['version']} | {get_app_info()['institution']}\n"
        
        self.details_text.insert("1.0", text)
        self.details_text.configure(state="disabled")
        
        # Atualizar painel de resumo rápido
        self._update_summary_panel(stats)
    
    def _update_summary_panel(self, stats):
        """Atualiza o painel de resumo rápido."""
        if not hasattr(self, 'summary_frame'):
            return
            
        # Limpar
        for widget in self.summary_frame.winfo_children():
            widget.destroy()
        
        # Severidades
        severity_card = ctk.CTkFrame(self.summary_frame, fg_color=theme.BG_TERTIARY, corner_radius=8)
        severity_card.pack(fill="x", padx=10, pady=10)
        
        ctk.CTkLabel(
            severity_card,
            text="🎯 Por Severidade",
            font=Fonts.subheading(),
            text_color=theme.TEXT_PRIMARY
        ).pack(anchor="w", padx=12, pady=(10, 5))
        
        severity_colors = {
            'CRITICAL': theme.CRITICAL,
            'HIGH': theme.HIGH,
            'MEDIUM': theme.MEDIUM,
            'LOW': theme.LOW
        }
        
        for sev, count in stats['by_severity'].items():
            row = ctk.CTkFrame(severity_card, fg_color="transparent")
            row.pack(fill="x", padx=12, pady=2)
            
            # Indicador de cor
            ctk.CTkLabel(
                row,
                text="●",
                font=ctk.CTkFont(size=12),
                text_color=severity_colors.get(sev, theme.TEXT_MUTED)
            ).pack(side="left")
            
            ctk.CTkLabel(
                row,
                text=f"  {sev}",
                font=Fonts.small(),
                text_color=theme.TEXT_SECONDARY
            ).pack(side="left")
            
            ctk.CTkLabel(
                row,
                text=str(count),
                font=ctk.CTkFont(family=theme.FONT_FAMILY, size=12, weight="bold"),
                text_color=severity_colors.get(sev, theme.TEXT_PRIMARY)
            ).pack(side="right", padx=(0, 5))
        
        ctk.CTkFrame(severity_card, height=10, fg_color="transparent").pack()
        
        # Top IPs
        if stats.get('top_ips'):
            ip_card = ctk.CTkFrame(self.summary_frame, fg_color=theme.BG_TERTIARY, corner_radius=8)
            ip_card.pack(fill="x", padx=10, pady=(0, 10))
            
            ctk.CTkLabel(
                ip_card,
                text="🌐 Top IPs Suspeitos",
                font=Fonts.subheading(),
                text_color=theme.TEXT_PRIMARY
            ).pack(anchor="w", padx=12, pady=(10, 5))
            
            for ip, count in stats['top_ips'][:5]:
                row = ctk.CTkFrame(ip_card, fg_color="transparent")
                row.pack(fill="x", padx=12, pady=2)
                
                ctk.CTkLabel(
                    row,
                    text=ip,
                    font=Fonts.mono_small(),
                    text_color=theme.TEXT_SECONDARY
                ).pack(side="left")
                
                ctk.CTkLabel(
                    row,
                    text=str(count),
                    font=Fonts.body(),
                    text_color=theme.ACCENT_PRIMARY
                ).pack(side="right")
            
            ctk.CTkFrame(ip_card, height=10, fg_color="transparent").pack()
        
        # Ações rápidas
        actions_card = ctk.CTkFrame(self.summary_frame, fg_color=theme.BG_TERTIARY, corner_radius=8)
        actions_card.pack(fill="x", padx=10, pady=(0, 10))
        
        ctk.CTkLabel(
            actions_card,
            text="⚡ Ações Rápidas",
            font=Fonts.subheading(),
            text_color=theme.TEXT_PRIMARY
        ).pack(anchor="w", padx=12, pady=(10, 10))
        
        btn_frame = ctk.CTkFrame(actions_card, fg_color="transparent")
        btn_frame.pack(fill="x", padx=12, pady=(0, 12))
        
        ctk.CTkButton(
            btn_frame,
            text="📄 Exportar PDF",
            font=Fonts.small(),
            fg_color=theme.ACCENT_PRIMARY,
            hover_color=theme.ACCENT_HOVER,
            height=32,
            command=lambda: self._export_report()
        ).pack(fill="x", pady=2)
        
        ctk.CTkButton(
            btn_frame,
            text="📊 Exportar CSV",
            font=Fonts.small(),
            fg_color="transparent",
            hover_color=theme.BG_HOVER,
            border_width=1,
            border_color=theme.BORDER_PRIMARY,
            text_color=theme.TEXT_SECONDARY,
            height=32,
            command=lambda: self._export_report()
        ).pack(fill="x", pady=2)
    
    def _update_timeline(self):
        """Atualiza timeline com filtros e layout adaptativo."""
        self.timeline_canvas.delete("all")
        
        if not self.anomalies:
            canvas_width = self.timeline_canvas.winfo_width() or 800
            canvas_height = self.timeline_canvas.winfo_height() or 400
            self.timeline_canvas.create_text(
                canvas_width // 2, canvas_height // 2,
                text="Carregue um log e execute a análise para ver a timeline",
                fill=theme.TEXT_MUTED,
                font=(theme.FONT_FAMILY, 14)
            )
            if hasattr(self, 'timeline_info'):
                self.timeline_info.configure(text="")
            return
        
        # Obter filtros
        period_filter = self.timeline_period.get() if hasattr(self, 'timeline_period') else "Todas as horas"
        group_by = self.timeline_group.get() if hasattr(self, 'timeline_group') else "Por hora"
        
        # Determinar intervalo de agrupamento
        if group_by == "Por 30 min":
            time_format = "%H:%M"
            interval_mins = 30
        elif group_by == "Por 15 min":
            time_format = "%H:%M"
            interval_mins = 15
        else:  # Por hora
            time_format = "%H:00"
            interval_mins = 60
        
        # Filtrar e agrupar anomalias
        from collections import defaultdict
        hourly_data = defaultdict(lambda: {'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'files': set()})
        
        for anomaly in self.anomalies:
            if not anomaly.timestamp:
                continue
            
            hour = anomaly.timestamp.hour
            
            # Aplicar filtro de período
            if period_filter == "Últimas 6h":
                from datetime import datetime, timedelta
                cutoff = datetime.now() - timedelta(hours=6)
                if anomaly.timestamp < cutoff:
                    continue
            elif period_filter == "Últimas 12h":
                from datetime import datetime, timedelta
                cutoff = datetime.now() - timedelta(hours=12)
                if anomaly.timestamp < cutoff:
                    continue
            elif period_filter == "Horário trabalho (8h-18h)":
                if hour < 8 or hour >= 18:
                    continue
            elif period_filter == "Fora de horário":
                if 8 <= hour < 18:
                    continue
            
            # Calcular chave de tempo
            if interval_mins == 60:
                time_key = anomaly.timestamp.strftime("%H:00")
            elif interval_mins == 30:
                minute_group = (anomaly.timestamp.minute // 30) * 30
                time_key = f"{hour:02d}:{minute_group:02d}"
            else:  # 15 min
                minute_group = (anomaly.timestamp.minute // 15) * 15
                time_key = f"{hour:02d}:{minute_group:02d}"
            
            hourly_data[time_key]['total'] += 1
            severity = anomaly.severity.value.lower()
            if severity in hourly_data[time_key]:
                hourly_data[time_key][severity] += 1
            
            if hasattr(anomaly, 'log_file') and anomaly.log_file:
                hourly_data[time_key]['files'].add(os.path.basename(anomaly.log_file))
        
        if not hourly_data:
            canvas_width = self.timeline_canvas.winfo_width() or 800
            canvas_height = self.timeline_canvas.winfo_height() or 400
            self.timeline_canvas.create_text(
                canvas_width // 2, canvas_height // 2,
                text="Sem dados para o filtro selecionado",
                fill=theme.TEXT_MUTED,
                font=(theme.FONT_FAMILY, 14)
            )
            if hasattr(self, 'timeline_info'):
                self.timeline_info.configure(text="Tente alterar os filtros")
            return
        
        # Ordenar por tempo
        sorted_hours = sorted(hourly_data.keys())
        data = [(h, hourly_data[h]) for h in sorted_hours]
        
        # Obter dimensões do canvas
        self.timeline_canvas.update_idletasks()
        width = max(self.timeline_canvas.winfo_width(), 800)
        height = max(self.timeline_canvas.winfo_height(), 450)
        
        # Margens - mais espaço para o gráfico
        margin_left = 60
        margin_right = 40
        margin_top = 30
        margin_bottom = 80
        
        chart_width = width - margin_left - margin_right
        chart_height = height - margin_top - margin_bottom
        
        max_val = max(d[1]['total'] for d in data) or 1
        
        # Eixo Y
        self.timeline_canvas.create_line(
            margin_left, margin_top,
            margin_left, height - margin_bottom,
            fill=theme.BORDER_PRIMARY, width=2
        )
        
        # Eixo X
        self.timeline_canvas.create_line(
            margin_left, height - margin_bottom,
            width - margin_right, height - margin_bottom,
            fill=theme.BORDER_PRIMARY, width=2
        )
        
        # Marcas no eixo Y (mais marcas para maior precisão)
        num_y_marks = min(max_val + 1, 8)
        for i in range(num_y_marks):
            y = margin_top + (chart_height * i / (num_y_marks - 1)) if num_y_marks > 1 else margin_top
            val = int(max_val * (num_y_marks - 1 - i) / (num_y_marks - 1)) if num_y_marks > 1 else max_val
            self.timeline_canvas.create_text(
                margin_left - 12, y,
                text=str(val),
                fill=theme.TEXT_MUTED,
                font=(theme.FONT_FAMILY, 10),
                anchor="e"
            )
            # Linha de grade
            self.timeline_canvas.create_line(
                margin_left, y,
                width - margin_right, y,
                fill=theme.BG_TERTIARY, dash=(3, 5)
            )
        
        # Cores por severidade
        severity_order = ['low', 'medium', 'high', 'critical']
        severity_colors = {
            'critical': theme.CRITICAL,
            'high': theme.HIGH,
            'medium': theme.MEDIUM,
            'low': theme.LOW,
        }
        
        # Calcular largura das barras - ADAPTAR ao número de barras
        num_bars = len(data)
        if num_bars == 1:
            bar_width = min(150, chart_width * 0.3)
        elif num_bars <= 4:
            bar_width = min(100, chart_width / (num_bars + 1))
        elif num_bars <= 10:
            bar_width = min(70, chart_width / (num_bars * 1.2))
        else:
            bar_width = max(30, chart_width / (num_bars * 1.3))
        
        total_bars_width = bar_width * num_bars
        spacing = (chart_width - total_bars_width) / (num_bars + 1) if num_bars > 0 else 0
        
        # Desenhar barras
        for i, (hour, counts) in enumerate(data):
            if num_bars == 1:
                x = margin_left + chart_width / 2
            else:
                x = margin_left + spacing * (i + 1) + bar_width * i + bar_width / 2
            
            y_bottom = height - margin_bottom
            current_y = y_bottom
            
            # Barras empilhadas
            for sev in severity_order:
                count = counts.get(sev, 0)
                if count > 0:
                    seg_height = (count / max_val) * chart_height
                    seg_top = current_y - seg_height
                    
                    # Barra
                    self.timeline_canvas.create_rectangle(
                        x - bar_width/2, seg_top,
                        x + bar_width/2, current_y,
                        fill=severity_colors[sev], outline=""
                    )
                    
                    # Número dentro da barra (se couber)
                    if seg_height > 18 and bar_width > 25:
                        self.timeline_canvas.create_text(
                            x, seg_top + seg_height/2,
                            text=str(count),
                            fill="#FFFFFF",
                            font=(theme.FONT_FAMILY, 9, 'bold')
                        )
                    
                    current_y = seg_top
            
            # Total no topo
            total_height = (counts['total'] / max_val) * chart_height
            y_top = y_bottom - total_height
            self.timeline_canvas.create_text(
                x, y_top - 12,
                text=str(counts['total']),
                fill=theme.TEXT_PRIMARY,
                font=(theme.FONT_FAMILY, 11, 'bold')
            )
            
            # Label da hora
            self.timeline_canvas.create_text(
                x, height - margin_bottom + 18,
                text=hour,
                fill=theme.TEXT_SECONDARY,
                font=(theme.FONT_FAMILY, 10)
            )
            
            # Indicador de múltiplos ficheiros
            if len(counts['files']) > 1:
                self.timeline_canvas.create_text(
                    x, height - margin_bottom + 35,
                    text=f"({len(counts['files'])}f)",
                    fill=theme.ACCENT_PRIMARY,
                    font=(theme.FONT_FAMILY, 8)
                )
        
        # Legenda no fundo
        legend_y = height - 25
        legend_items = [
            ('Critical', theme.CRITICAL, 'critical'),
            ('High', theme.HIGH, 'high'),
            ('Medium', theme.MEDIUM, 'medium'),
            ('Low', theme.LOW, 'low'),
        ]
        
        # Calcular totais
        totals = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        total_all = 0
        for _, counts in data:
            for sev in totals:
                totals[sev] += counts.get(sev, 0)
            total_all += counts['total']
        
        # Centrar legenda
        legend_total_width = len(legend_items) * 110
        legend_x = (width - legend_total_width) / 2
        
        for label, color, key in legend_items:
            self.timeline_canvas.create_rectangle(
                legend_x, legend_y - 6,
                legend_x + 14, legend_y + 6,
                fill=color, outline=""
            )
            text = f"{label}: {totals[key]}"
            self.timeline_canvas.create_text(
                legend_x + 18, legend_y,
                text=text,
                fill=theme.TEXT_SECONDARY,
                font=(theme.FONT_FAMILY, 10),
                anchor="w"
            )
            legend_x += 110
        
        # Info footer
        if hasattr(self, 'timeline_info'):
            num_files = len(self.loaded_files) if hasattr(self, 'loaded_files') and self.loaded_files else 1
            info_text = f"Total: {total_all} anomalias em {len(data)} períodos"
            if num_files > 1:
                info_text += f" • {num_files} ficheiros"
            self.timeline_info.configure(text=info_text)
    
    def _show_welcome_message(self):
        """Mostra mensagem de boas-vindas."""
        self.details_text.configure(state="normal")
        self.details_text.delete("1.0", "end")
        
        info = get_app_info()
        
        text = f"""

     🦉 LOG SENTINEL v{info['version']}
     ═══════════════════════════════════════════════════════

     Sistema de Análise e Deteção de Anomalias em Logs

     ───────────────────────────────────────────────────────

     FUNCIONALIDADES:

     • Dashboard com métricas em tempo real
     • Sistema de alertas com notificações
     • Timeline interativa de eventos
     • Correlação automática de eventos suspeitos
     • Exportação de relatórios (PDF, CSV, JSON, DOCX)
     • Sistema de plugins para deteção customizada
     • Machine Learning para deteção de anomalias

     ───────────────────────────────────────────────────────

     COMO USAR:

     1. Clique em "Carregar Log" para selecionar um ficheiro
     2. Clique em "Iniciar Análise" para processar
     3. Explore os resultados nas diferentes tabs
     4. Exporte relatórios conforme necessário

     ───────────────────────────────────────────────────────

     TIPOS DE ATAQUES DETETADOS:

     • SQL Injection        • XSS
     • Path Traversal       • Command Injection
     • Brute Force          • DDoS
     • Scanner Detection    • LFI/RFI
     • XXE                  • E mais...

     ───────────────────────────────────────────────────────

     Autor: {info['author']} (Nº {info['student_id']})
     {info['institution']}
     Ano Letivo: {info['year']}

"""
        self.details_text.insert("1.0", text)
        self.details_text.configure(state="disabled")
    
    def _filter_alerts(self, *args):
        """Filtra alertas."""
        # Recriar lista com filtros aplicados
        self._update_alerts()
    
    def _set_status(self, message: str):
        """Define mensagem de status."""
        self.status_text.configure(text=message)
    
    def _send_notification(self, title: str, message: str):
        """Envia notificação desktop."""
        if NOTIFICATIONS_AVAILABLE and config.get('ENABLE_NOTIFICATIONS', True):
            try:
                notification.notify(
                    title=title,
                    message=message,
                    app_name="Log Sentinel",
                    timeout=5
                )
            except:
                pass
    
    def _start_realtime_updates(self):
        """Inicia atualizações em tempo real."""
        def update():
            if not self.is_analyzing:
                self._update_metrics()
            self.after(30000, update)  # 30 segundos
        
        self.after(30000, update)


# Ponto de entrada
if __name__ == "__main__":
    ctk.set_appearance_mode("dark")
    app = LogSentinelApp()
    app.mainloop()
