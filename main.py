#!/usr/bin/env python3
"""
Log Sentinel v2.0 - Ponto de Entrada Principal
===============================================

Author: Duarte Cunha (Nº 2024271)
ISTEC - Instituto Superior de Tecnologias Avançadas de Lisboa
Ano Letivo: 2025/2026
"""

import sys
import os
import time

# Adicionar diretórios ao path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE_DIR, 'src'))


def check_dependencies():
    """Verifica se as dependências estão instaladas."""
    missing = []
    
    try:
        import customtkinter
    except ImportError:
        missing.append("customtkinter")
    
    try:
        from PIL import Image
    except ImportError:
        missing.append("pillow")
    
    if missing:
        print("⚠️  Dependências em falta:")
        for dep in missing:
            print(f"   - {dep}")
        print("\nInstale com: pip install -r requirements.txt")
        return False
    
    return True


def show_banner():
    """Mostra banner no console."""
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║              LOG SENTINEL v2.0                               ║
    ║       Sistema de Análise e Deteção de Anomalias              ║
    ║                                                              ║
    ║       Author: Duarte Cunha (Nº 2024271)                      ║
    ║       ISTEC • Ano Letivo 2025/2026                           ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)


def main():
    """Função principal - inicia a aplicação."""
    show_banner()
    
    print("  [*] A verificar dependências...")
    if not check_dependencies():
        sys.exit(1)
    print("  [✓] Dependências OK")
    
    print("  [*] A inicializar aplicação...")
    
    try:
        import customtkinter as ctk
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        # Importar componentes
        from gui.splash import SplashScreen
        from gui.main_window import LogSentinelApp
        
        print("  [✓] Módulos carregados")
        print("  [*] A abrir interface gráfica...\n")
        
        # Criar janela root escondida
        root = ctk.CTk()
        root.withdraw()
        
        # Mostrar splash screen
        splash = SplashScreen(root)
        splash.lift()
        splash.focus_force()
        
        # Simular carregamento
        stages = [
            (0.2, "A carregar módulos..."),
            (0.4, "A inicializar base de dados..."),
            (0.6, "A carregar plugins..."),
            (0.8, "A preparar interface..."),
            (1.0, "Pronto!"),
        ]
        
        for progress, status in stages:
            splash.set_progress(progress, status)
            splash.update()
            time.sleep(0.3)
        
        # Aguardar um pouco no final
        time.sleep(0.5)
        
        # Fechar splash
        splash.close()
        
        # Destruir root temporário
        root.destroy()
        
        # Criar e executar aplicação principal
        app = LogSentinelApp()
        app.mainloop()
        
    except ImportError as e:
        print(f"\n  [✗] Erro ao importar módulos: {e}")
        print("\n  Por favor, instale as dependências:")
        print("  pip install -r requirements.txt")
        sys.exit(1)
        
    except Exception as e:
        print(f"\n  [✗] Erro inesperado: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
