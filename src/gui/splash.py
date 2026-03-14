"""
Log Sentinel v2.0 - Splash Screen
==================================
Splash screen com logo da coruja e barra de loading.

Author: Duarte Cunha (Nº 2024271)
ISTEC - Instituto Superior de Tecnologias Avançadas de Lisboa
Ano Letivo: 2025/2026
"""

import customtkinter as ctk
from PIL import Image, ImageTk
import sys
import os
from pathlib import Path

# Obter diretório base
if getattr(sys, 'frozen', False):
    BASE_DIR = Path(sys._MEIPASS)
else:
    BASE_DIR = Path(__file__).parent.parent.parent

sys.path.insert(0, str(BASE_DIR / 'src'))

try:
    from utils.theme import theme
    from utils.config import get_app_info
except:
    # Fallback se não conseguir importar
    class theme:
        BG_PRIMARY = "#0f172a"
        BG_SECONDARY = "#1e293b"
        BG_TERTIARY = "#334155"
        ACCENT_PRIMARY = "#2E9E4B"
        TEXT_PRIMARY = "#f1f5f9"
        TEXT_SECONDARY = "#94a3b8"
        TEXT_MUTED = "#64748b"
    
    def get_app_info():
        return {
            'version': '2.0',
            'author': 'Duarte Cunha',
            'student_id': '2024271',
            'institution': 'ISTEC'
        }


class SplashScreen(ctk.CTkToplevel):
    """Splash screen com logo e barra de loading."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        
        # Configuração da janela
        self.overrideredirect(True)
        self.configure(fg_color=theme.BG_PRIMARY)
        
        # Dimensões
        width = 450
        height = 350
        
        # Centralizar na tela
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        x = (screen_width - width) // 2
        y = (screen_height - height) // 2
        self.geometry(f"{width}x{height}+{x}+{y}")
        
        # Conteúdo
        self._create_content()
        
        # Animação
        self.progress = 0
        self._animate()
    
    def _create_content(self):
        """Cria o conteúdo do splash."""
        # Container principal
        main = ctk.CTkFrame(self, fg_color=theme.BG_PRIMARY, corner_radius=0)
        main.pack(fill="both", expand=True)
        
        # Frame central
        content = ctk.CTkFrame(main, fg_color="transparent")
        content.pack(expand=True)
        
        # Carregar e mostrar logo PNG
        self._load_logo(content)
        
        # Título
        title_frame = ctk.CTkFrame(content, fg_color="transparent")
        title_frame.pack(pady=(20, 5))
        
        ctk.CTkLabel(
            title_frame,
            text="LOG",
            font=ctk.CTkFont(family="Segoe UI", size=32, weight="bold"),
            text_color=theme.ACCENT_PRIMARY
        ).pack(side="left")
        
        ctk.CTkLabel(
            title_frame,
            text=" SENTINEL",
            font=ctk.CTkFont(family="Segoe UI", size=32, weight="bold"),
            text_color=theme.TEXT_PRIMARY
        ).pack(side="left")
        
        # Subtítulo
        ctk.CTkLabel(
            content,
            text="Sistema de Análise e Deteção de Anomalias",
            font=ctk.CTkFont(size=11),
            text_color=theme.TEXT_SECONDARY
        ).pack(pady=(5, 30))
        
        # Barra de progresso
        progress_frame = ctk.CTkFrame(content, fg_color="transparent")
        progress_frame.pack(fill="x", padx=50)
        
        self.progress_bar = ctk.CTkProgressBar(
            progress_frame,
            width=300,
            height=6,
            corner_radius=3,
            fg_color=theme.BG_TERTIARY,
            progress_color=theme.ACCENT_PRIMARY
        )
        self.progress_bar.pack()
        self.progress_bar.set(0)
        
        # Status
        self.status_label = ctk.CTkLabel(
            content,
            text="A inicializar...",
            font=ctk.CTkFont(size=10),
            text_color=theme.TEXT_MUTED
        )
        self.status_label.pack(pady=(10, 0))
        
        # Footer
        info = get_app_info()
        ctk.CTkLabel(
            content,
            text=f"v{info['version']} • {info['author']} • {info['institution']}",
            font=ctk.CTkFont(size=9),
            text_color=theme.TEXT_MUTED
        ).pack(pady=(20, 0))
    
    def _load_logo(self, parent):
        """Carrega e exibe o logo PNG."""
        # Tentar encontrar o logo
        possible_paths = [
            BASE_DIR / "assets" / "icons" / "owl_logo.png",
            BASE_DIR / "assets" / "icons" / "owl_logo_256.png",
            Path(__file__).parent.parent.parent / "assets" / "icons" / "owl_logo.png",
            Path(__file__).parent.parent.parent / "assets" / "icons" / "owl_logo_256.png",
        ]
        
        logo_path = None
        for path in possible_paths:
            if path.exists():
                logo_path = path
                break
        
        if logo_path:
            try:
                # Carregar imagem
                img = Image.open(logo_path)
                
                # Redimensionar para 120x120
                img = img.resize((120, 120), Image.Resampling.LANCZOS)
                
                # Converter para CTkImage
                self.logo_image = ctk.CTkImage(
                    light_image=img,
                    dark_image=img,
                    size=(120, 120)
                )
                
                # Criar label com imagem
                logo_label = ctk.CTkLabel(
                    parent,
                    image=self.logo_image,
                    text=""
                )
                logo_label.pack(pady=(0, 0))
                return
            except Exception as e:
                print(f"Erro ao carregar logo: {e}")
        
        # Fallback: emoji se não encontrar o logo
        ctk.CTkLabel(
            parent,
            text="🦉",
            font=ctk.CTkFont(size=80),
            text_color=theme.ACCENT_PRIMARY
        ).pack()
    
    def _animate(self):
        """Animação do splash."""
        if not self.winfo_exists():
            return
        
        # Atualizar progresso
        self.progress += 0.02
        if self.progress > 1:
            self.progress = 1
        
        self.progress_bar.set(self.progress)
        
        # Atualizar status
        if self.progress < 0.3:
            status = "A carregar módulos..."
        elif self.progress < 0.5:
            status = "A inicializar base de dados..."
        elif self.progress < 0.7:
            status = "A carregar plugins..."
        elif self.progress < 0.9:
            status = "A preparar interface..."
        else:
            status = "Pronto!"
        
        self.status_label.configure(text=status)
        
        # Continuar animação
        if self.progress < 1:
            self.after(50, self._animate)
    
    def set_progress(self, value: float, status: str = None):
        """Define progresso manualmente."""
        self.progress = value
        self.progress_bar.set(value)
        if status:
            self.status_label.configure(text=status)
    
    def close(self):
        """Fecha o splash."""
        self.destroy()


class SplashManager:
    """Gestor do splash screen."""
    
    def __init__(self):
        self.splash = None
        self.root = None
    
    def show(self) -> ctk.CTk:
        """Mostra splash e retorna root escondido."""
        self.root = ctk.CTk()
        self.root.withdraw()
        
        self.splash = SplashScreen(self.root)
        self.splash.lift()
        self.splash.focus_force()
        
        return self.root
    
    def update(self, progress: float, status: str = None):
        """Atualiza splash."""
        if self.splash:
            self.splash.set_progress(progress, status)
            self.splash.update()
    
    def close(self):
        """Fecha splash e mostra root."""
        if self.splash:
            self.splash.close()
            self.splash = None
        
        if self.root:
            self.root.deiconify()
        
        return self.root


# Demo/teste
if __name__ == "__main__":
    ctk.set_appearance_mode("dark")
    
    root = ctk.CTk()
    root.withdraw()
    
    splash = SplashScreen(root)
    
    def on_complete():
        splash.destroy()
        root.destroy()
    
    root.after(3000, on_complete)
    root.mainloop()
