"""
Log Sentinel v2.0 - UI Components
==================================
Componentes reutilizáveis da interface gráfica.

Author: Duarte Cunha (Nº 2024271)
ISTEC - Instituto Superior de Tecnologias Avançadas de Lisboa
Ano Letivo: 2025/2026
"""

import customtkinter as ctk
from typing import Callable, Optional, List, Dict, Any
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.theme import theme, Icons, Fonts


class Card(ctk.CTkFrame):
    """Card container com estilo consistente."""
    
    def __init__(self, parent, title: str = None, **kwargs):
        super().__init__(
            parent,
            fg_color=theme.BG_CARD,
            corner_radius=theme.RADIUS_LG,
            border_width=1,
            border_color=theme.BORDER_PRIMARY,
            **kwargs
        )
        
        if title:
            self.title_label = ctk.CTkLabel(
                self,
                text=title,
                font=Fonts.subheading(),
                text_color=theme.TEXT_PRIMARY
            )
            self.title_label.pack(anchor="w", padx=16, pady=(16, 8))


class MetricCard(ctk.CTkFrame):
    """Card para exibir métricas com valor e label."""
    
    def __init__(self, parent, title: str, value: str = "0", 
                 icon: str = None, color: str = None, **kwargs):
        super().__init__(
            parent,
            fg_color=theme.BG_CARD,
            corner_radius=theme.RADIUS_LG,
            border_width=1,
            border_color=theme.BORDER_PRIMARY,
            **kwargs
        )
        
        self.color = color or theme.ACCENT_PRIMARY
        
        # Container interno
        inner = ctk.CTkFrame(self, fg_color="transparent")
        inner.pack(fill="both", expand=True, padx=16, pady=16)
        
        # Header com ícone
        header = ctk.CTkFrame(inner, fg_color="transparent")
        header.pack(fill="x")
        
        if icon:
            icon_label = ctk.CTkLabel(
                header,
                text=icon,
                font=ctk.CTkFont(size=20),
                text_color=self.color
            )
            icon_label.pack(side="left")
        
        title_label = ctk.CTkLabel(
            header,
            text=title,
            font=Fonts.small(),
            text_color=theme.TEXT_SECONDARY
        )
        title_label.pack(side="left", padx=(8 if icon else 0, 0))
        
        # Valor
        self.value_label = ctk.CTkLabel(
            inner,
            text=value,
            font=ctk.CTkFont(family=theme.FONT_FAMILY, size=32, weight="bold"),
            text_color=self.color
        )
        self.value_label.pack(anchor="w", pady=(8, 0))
    
    def set_value(self, value: str):
        """Atualiza o valor."""
        self.value_label.configure(text=value)
    
    def set_color(self, color: str):
        """Atualiza a cor."""
        self.color = color
        self.value_label.configure(text_color=color)


class AlertItem(ctk.CTkFrame):
    """Item de alerta na lista."""
    
    def __init__(self, parent, anomaly_type: str, severity: str,
                 detail: str, source_ip: str = None, timestamp: str = None,
                 on_click: Callable = None, **kwargs):
        super().__init__(
            parent,
            fg_color=theme.BG_TERTIARY,
            corner_radius=theme.RADIUS_MD,
            **kwargs
        )
        
        self.on_click = on_click
        
        # Indicador de severidade
        severity_colors = {
            'CRITICAL': theme.CRITICAL,
            'HIGH': theme.HIGH,
            'MEDIUM': theme.MEDIUM,
            'LOW': theme.LOW,
        }
        color = severity_colors.get(severity, theme.TEXT_SECONDARY)
        
        # Container principal
        main = ctk.CTkFrame(self, fg_color="transparent")
        main.pack(fill="both", expand=True, padx=12, pady=10)
        
        # Header
        header = ctk.CTkFrame(main, fg_color="transparent")
        header.pack(fill="x")
        
        # Indicador colorido
        indicator = ctk.CTkFrame(header, width=4, height=40, fg_color=color, corner_radius=2)
        indicator.pack(side="left", padx=(0, 10))
        indicator.pack_propagate(False)
        
        # Info
        info = ctk.CTkFrame(header, fg_color="transparent")
        info.pack(side="left", fill="x", expand=True)
        
        # Tipo e severidade
        type_frame = ctk.CTkFrame(info, fg_color="transparent")
        type_frame.pack(fill="x")
        
        type_label = ctk.CTkLabel(
            type_frame,
            text=anomaly_type,
            font=Fonts.subheading(),
            text_color=theme.TEXT_PRIMARY
        )
        type_label.pack(side="left")
        
        severity_badge = ctk.CTkLabel(
            type_frame,
            text=severity,
            font=Fonts.small(),
            text_color=color,
            fg_color=theme.get_severity_bg(severity),
            corner_radius=4,
            padx=8,
            pady=2
        )
        severity_badge.pack(side="left", padx=(8, 0))
        
        # Detalhe
        detail_label = ctk.CTkLabel(
            info,
            text=detail[:80] + "..." if len(detail) > 80 else detail,
            font=Fonts.small(),
            text_color=theme.TEXT_SECONDARY,
            anchor="w"
        )
        detail_label.pack(fill="x", pady=(4, 0))
        
        # Footer com IP e timestamp
        footer = ctk.CTkFrame(info, fg_color="transparent")
        footer.pack(fill="x", pady=(4, 0))
        
        if source_ip:
            ip_label = ctk.CTkLabel(
                footer,
                text=f"IP: {source_ip}",
                font=Fonts.mono_small(),
                text_color=theme.TEXT_MUTED
            )
            ip_label.pack(side="left")
        
        if timestamp:
            time_label = ctk.CTkLabel(
                footer,
                text=timestamp,
                font=Fonts.small(),
                text_color=theme.TEXT_MUTED
            )
            time_label.pack(side="right")
        
        # Bind click
        if on_click:
            self.bind("<Button-1>", lambda e: on_click())
            for widget in self.winfo_children():
                widget.bind("<Button-1>", lambda e: on_click())


class ProgressBar(ctk.CTkFrame):
    """Barra de progresso customizada."""
    
    def __init__(self, parent, height: int = 8, color: str = None, **kwargs):
        super().__init__(
            parent,
            fg_color=theme.BG_TERTIARY,
            corner_radius=height // 2,
            height=height,
            **kwargs
        )
        self.pack_propagate(False)
        
        self.color = color or theme.ACCENT_PRIMARY
        self.progress = 0
        
        self.fill = ctk.CTkFrame(
            self,
            fg_color=self.color,
            corner_radius=height // 2,
            height=height
        )
        self.fill.place(relx=0, rely=0, relheight=1, relwidth=0)
    
    def set_progress(self, value: float):
        """Define progresso (0.0 a 1.0)."""
        self.progress = max(0, min(1, value))
        self.fill.place_configure(relwidth=self.progress)
    
    def set_color(self, color: str):
        """Define cor."""
        self.color = color
        self.fill.configure(fg_color=color)


class SearchBar(ctk.CTkFrame):
    """Barra de pesquisa."""
    
    def __init__(self, parent, placeholder: str = "Pesquisar...",
                 on_search: Callable = None, **kwargs):
        super().__init__(parent, fg_color="transparent", **kwargs)
        
        self.on_search = on_search
        
        # Container
        container = ctk.CTkFrame(
            self,
            fg_color=theme.BG_INPUT,
            corner_radius=theme.RADIUS_MD,
            border_width=1,
            border_color=theme.BORDER_PRIMARY
        )
        container.pack(fill="x")
        
        # Ícone
        icon = ctk.CTkLabel(
            container,
            text=Icons.SEARCH,
            font=ctk.CTkFont(size=14),
            text_color=theme.TEXT_MUTED,
            width=30
        )
        icon.pack(side="left", padx=(10, 0))
        
        # Entry
        self.entry = ctk.CTkEntry(
            container,
            placeholder_text=placeholder,
            font=Fonts.body(),
            fg_color="transparent",
            border_width=0,
            text_color=theme.TEXT_PRIMARY
        )
        self.entry.pack(side="left", fill="x", expand=True, padx=5, pady=8)
        
        # Bind Enter
        self.entry.bind("<Return>", self._on_enter)
    
    def _on_enter(self, event):
        if self.on_search:
            self.on_search(self.entry.get())
    
    def get(self) -> str:
        return self.entry.get()
    
    def clear(self):
        self.entry.delete(0, "end")


class TabView(ctk.CTkFrame):
    """Tab view customizado com transições suaves."""
    
    def __init__(self, parent, tabs: List[str], **kwargs):
        super().__init__(parent, fg_color="transparent", **kwargs)
        
        self.tabs = tabs
        self.current_tab = 0
        self.tab_buttons: List[ctk.CTkButton] = []
        self.tab_frames: Dict[int, ctk.CTkFrame] = {}
        self.on_tab_change: Optional[Callable] = None
        self._animating = False
        
        # Header com tabs
        self.header = ctk.CTkFrame(self, fg_color=theme.BG_SECONDARY, corner_radius=8, height=50)
        self.header.pack(fill="x", pady=(0, 10))
        self.header.pack_propagate(False)
        
        # Container para botões centrados
        btn_container = ctk.CTkFrame(self.header, fg_color="transparent")
        btn_container.pack(expand=True, pady=5)
        
        for i, tab_name in enumerate(tabs):
            btn = ctk.CTkButton(
                btn_container,
                text=tab_name,
                font=Fonts.body(),
                fg_color="transparent",
                hover_color=theme.BG_HOVER,
                text_color=theme.TEXT_SECONDARY,
                corner_radius=6,
                height=36,
                width=120,
                command=lambda idx=i: self._animate_tab_change(idx)
            )
            btn.pack(side="left", padx=3)
            self.tab_buttons.append(btn)
        
        # Container para conteúdo com fundo
        self.content = ctk.CTkFrame(self, fg_color="transparent")
        self.content.pack(fill="both", expand=True)
        
        # Selecionar primeira tab (sem animação)
        self._select_tab_instant(0)
    
    def _animate_tab_change(self, index: int):
        """Muda de tab com efeito de fade."""
        if self._animating or index == self.current_tab:
            return
        
        self._animating = True
        
        # Esconder tab atual rapidamente
        if self.current_tab in self.tab_frames:
            self.tab_frames[self.current_tab].pack_forget()
        
        # Atualizar botões imediatamente
        self._update_buttons(index)
        
        # Mostrar nova tab
        self.current_tab = index
        if index in self.tab_frames:
            self.tab_frames[index].pack(fill="both", expand=True)
        
        # Callback
        if self.on_tab_change:
            self.on_tab_change(index)
        
        # Reset animating flag após pequeno delay
        self.after(50, self._reset_animation)
    
    def _reset_animation(self):
        self._animating = False
    
    def _update_buttons(self, active_index: int):
        """Atualiza aparência dos botões."""
        for i, btn in enumerate(self.tab_buttons):
            if i == active_index:
                btn.configure(
                    fg_color=theme.ACCENT_PRIMARY,
                    text_color="#ffffff",
                    hover_color=theme.ACCENT_HOVER
                )
            else:
                btn.configure(
                    fg_color="transparent",
                    text_color=theme.TEXT_SECONDARY,
                    hover_color=theme.BG_HOVER
                )
    
    def _select_tab_instant(self, index: int):
        """Seleciona tab instantaneamente (sem animação)."""
        self.current_tab = index
        self._update_buttons(index)
        
        # Mostrar/esconder frames
        for idx, frame in self.tab_frames.items():
            if idx == index:
                frame.pack(fill="both", expand=True)
            else:
                frame.pack_forget()
    
    def select_tab(self, index: int):
        """Seleciona uma tab (com animação)."""
        self._animate_tab_change(index)
    
    def get_tab_frame(self, index: int) -> ctk.CTkFrame:
        """Obtém ou cria frame para uma tab."""
        if index not in self.tab_frames:
            frame = ctk.CTkFrame(self.content, fg_color="transparent")
            self.tab_frames[index] = frame
            if index == self.current_tab:
                frame.pack(fill="both", expand=True)
        return self.tab_frames[index]


class StatusIndicator(ctk.CTkFrame):
    """Indicador de status."""
    
    def __init__(self, parent, status: str = "offline", **kwargs):
        super().__init__(parent, fg_color="transparent", **kwargs)
        
        self.dot = ctk.CTkLabel(
            self,
            text="●",
            font=ctk.CTkFont(size=10),
            text_color=theme.TEXT_MUTED
        )
        self.dot.pack(side="left")
        
        self.label = ctk.CTkLabel(
            self,
            text=status,
            font=Fonts.small(),
            text_color=theme.TEXT_SECONDARY
        )
        self.label.pack(side="left", padx=(4, 0))
        
        self.set_status(status)
    
    def set_status(self, status: str):
        """Define status."""
        status_colors = {
            'online': theme.SUCCESS,
            'offline': theme.TEXT_MUTED,
            'scanning': theme.WARNING,
            'error': theme.ERROR,
            'ready': theme.ACCENT_PRIMARY,
        }
        color = status_colors.get(status.lower(), theme.TEXT_MUTED)
        self.dot.configure(text_color=color)
        self.label.configure(text=status.upper())


class Tooltip:
    """Tooltip para widgets."""
    
    def __init__(self, widget, text: str):
        self.widget = widget
        self.text = text
        self.tooltip_window = None
        
        widget.bind("<Enter>", self.show)
        widget.bind("<Leave>", self.hide)
    
    def show(self, event=None):
        x, y, _, _ = self.widget.bbox("insert") if hasattr(self.widget, 'bbox') else (0, 0, 0, 0)
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 25
        
        self.tooltip_window = tw = ctk.CTkToplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        
        label = ctk.CTkLabel(
            tw,
            text=self.text,
            font=Fonts.small(),
            fg_color=theme.BG_TERTIARY,
            text_color=theme.TEXT_PRIMARY,
            corner_radius=4,
            padx=8,
            pady=4
        )
        label.pack()
    
    def hide(self, event=None):
        if self.tooltip_window:
            self.tooltip_window.destroy()
            self.tooltip_window = None


class ConfirmDialog(ctk.CTkToplevel):
    """Diálogo de confirmação."""
    
    def __init__(self, parent, title: str, message: str,
                 on_confirm: Callable = None, on_cancel: Callable = None):
        super().__init__(parent)
        
        self.title(title)
        self.geometry("400x180")
        self.configure(fg_color=theme.BG_PRIMARY)
        self.resizable(False, False)
        
        # Centralizar
        self.transient(parent)
        self.grab_set()
        
        self.on_confirm = on_confirm
        self.on_cancel = on_cancel
        self.result = False
        
        # Conteúdo
        content = ctk.CTkFrame(self, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=24, pady=24)
        
        # Ícone e mensagem
        msg_label = ctk.CTkLabel(
            content,
            text=message,
            font=Fonts.body(),
            text_color=theme.TEXT_PRIMARY,
            wraplength=350
        )
        msg_label.pack(pady=(0, 24))
        
        # Botões
        btn_frame = ctk.CTkFrame(content, fg_color="transparent")
        btn_frame.pack(fill="x")
        
        cancel_btn = ctk.CTkButton(
            btn_frame,
            text="Cancelar",
            font=Fonts.body(),
            fg_color="transparent",
            hover_color=theme.BG_HOVER,
            text_color=theme.TEXT_SECONDARY,
            border_width=1,
            border_color=theme.BORDER_PRIMARY,
            width=120,
            command=self._cancel
        )
        cancel_btn.pack(side="right", padx=(8, 0))
        
        confirm_btn = ctk.CTkButton(
            btn_frame,
            text="Confirmar",
            font=Fonts.body(),
            fg_color=theme.ACCENT_PRIMARY,
            hover_color=theme.ACCENT_HOVER,
            text_color=theme.TEXT_PRIMARY,
            width=120,
            command=self._confirm
        )
        confirm_btn.pack(side="right")
    
    def _confirm(self):
        self.result = True
        if self.on_confirm:
            self.on_confirm()
        self.destroy()
    
    def _cancel(self):
        self.result = False
        if self.on_cancel:
            self.on_cancel()
        self.destroy()


if __name__ == "__main__":
    print("UI Components loaded successfully")
