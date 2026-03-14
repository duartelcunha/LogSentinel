#!/usr/bin/env python3
"""
Log Sentinel v2.0 - Instalador
===============================
Script de instalação que:
- Instala dependências
- Cria atalho no desktop
- Configura a aplicação

Author: Duarte Cunha (Nº 2024271)
ISTEC - 2025/2026

Uso:
    python install.py
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path
import platform


def print_banner():
    """Mostra banner do instalador."""
    print("""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║             LOG SENTINEL v2.0 - INSTALADOR                   ║
║                                                              ║
║       Sistema de Análise e Deteção de Anomalias              ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
    """)


def check_python():
    """Verifica versão do Python."""
    print("[1/5] A verificar Python...")
    
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print(f"  ✗ Python 3.8+ necessário (atual: {version.major}.{version.minor})")
        return False
    
    print(f"  ✓ Python {version.major}.{version.minor}.{version.micro}")
    return True


def install_dependencies():
    """Instala dependências do requirements.txt."""
    print("\n[2/5] A instalar dependências...")
    
    requirements_path = Path(__file__).parent / "requirements.txt"
    
    if not requirements_path.exists():
        print("  ✗ requirements.txt não encontrado")
        return False
    
    try:
        subprocess.check_call([
            sys.executable, "-m", "pip", "install", "-r", 
            str(requirements_path), "--quiet"
        ])
        print("  ✓ Dependências instaladas")
        return True
    except subprocess.CalledProcessError as e:
        print(f"  ✗ Erro ao instalar dependências: {e}")
        return False


def create_directories():
    """Cria diretórios necessários."""
    print("\n[3/5] A criar diretórios...")
    
    base_dir = Path(__file__).parent
    dirs = [
        base_dir / "data",
        base_dir / "data" / "logs",
        base_dir / "data" / "models",
        base_dir / "data" / "reports",
    ]
    
    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)
    
    print("  ✓ Diretórios criados")
    return True


def create_desktop_shortcut():
    """Cria atalho no desktop."""
    print("\n[4/5] A criar atalho no desktop...")
    
    system = platform.system()
    base_dir = Path(__file__).parent
    main_script = base_dir / "main.py"
    
    if system == "Windows":
        return create_windows_shortcut(base_dir, main_script)
    elif system == "Linux":
        return create_linux_shortcut(base_dir, main_script)
    elif system == "Darwin":  # macOS
        return create_macos_shortcut(base_dir, main_script)
    else:
        print(f"  ⚠ Sistema {system} não suportado para atalhos")
        return True


def create_windows_shortcut(base_dir: Path, main_script: Path) -> bool:
    """Cria atalho no Windows."""
    try:
        import winshell
        from win32com.client import Dispatch
        
        desktop = winshell.desktop()
        shortcut_path = os.path.join(desktop, "Log Sentinel.lnk")
        
        shell = Dispatch('WScript.Shell')
        shortcut = shell.CreateShortCut(shortcut_path)
        shortcut.Targetpath = sys.executable
        shortcut.Arguments = f'"{main_script}"'
        shortcut.WorkingDirectory = str(base_dir)
        shortcut.Description = "Log Sentinel - Security Analysis System"
        
        # Tentar definir ícone
        icon_path = base_dir / "assets" / "icons" / "owl_logo.ico"
        if icon_path.exists():
            shortcut.IconLocation = str(icon_path)
        
        shortcut.save()
        print(f"  ✓ Atalho criado: {shortcut_path}")
        return True
        
    except ImportError:
        # Sem winshell, criar .bat
        return create_windows_batch(base_dir, main_script)
    except Exception as e:
        print(f"  ⚠ Não foi possível criar atalho: {e}")
        return create_windows_batch(base_dir, main_script)


def create_windows_batch(base_dir: Path, main_script: Path) -> bool:
    """Cria ficheiro .bat para Windows."""
    try:
        # Criar launcher
        launcher_path = base_dir / "LogSentinel.bat"
        with open(launcher_path, 'w') as f:
            f.write(f'@echo off\n')
            f.write(f'cd /d "{base_dir}"\n')
            f.write(f'"{sys.executable}" "{main_script}"\n')
        
        # Copiar para desktop
        desktop = Path.home() / "Desktop"
        if desktop.exists():
            shutil.copy(launcher_path, desktop / "LogSentinel.bat")
            print(f"  ✓ Launcher criado no Desktop")
        else:
            print(f"  ✓ Launcher criado: {launcher_path}")
        
        return True
    except Exception as e:
        print(f"  ⚠ Erro ao criar launcher: {e}")
        return True


def create_linux_shortcut(base_dir: Path, main_script: Path) -> bool:
    """Cria atalho no Linux (.desktop)."""
    try:
        desktop_entry = f"""[Desktop Entry]
Version=1.0
Type=Application
Name=Log Sentinel
Comment=Security Analysis System
Exec={sys.executable} {main_script}
Icon={base_dir / "assets" / "icons" / "owl_logo.svg"}
Path={base_dir}
Terminal=false
Categories=Security;Development;
"""
        
        # Criar em ~/.local/share/applications
        apps_dir = Path.home() / ".local" / "share" / "applications"
        apps_dir.mkdir(parents=True, exist_ok=True)
        
        desktop_file = apps_dir / "logsentinel.desktop"
        with open(desktop_file, 'w') as f:
            f.write(desktop_entry)
        
        os.chmod(desktop_file, 0o755)
        
        # Copiar para Desktop
        desktop = Path.home() / "Desktop"
        if desktop.exists():
            desktop_shortcut = desktop / "LogSentinel.desktop"
            with open(desktop_shortcut, 'w') as f:
                f.write(desktop_entry)
            os.chmod(desktop_shortcut, 0o755)
            print(f"  ✓ Atalho criado no Desktop")
        
        print(f"  ✓ Aplicação registada no sistema")
        return True
        
    except Exception as e:
        print(f"  ⚠ Erro ao criar atalho: {e}")
        return True


def create_macos_shortcut(base_dir: Path, main_script: Path) -> bool:
    """Cria atalho no macOS."""
    try:
        # Criar script launcher
        launcher = base_dir / "LogSentinel.command"
        with open(launcher, 'w') as f:
            f.write("#!/bin/bash\n")
            f.write(f'cd "{base_dir}"\n')
            f.write(f'"{sys.executable}" "{main_script}"\n')
        
        os.chmod(launcher, 0o755)
        
        # Copiar para Desktop
        desktop = Path.home() / "Desktop"
        if desktop.exists():
            shutil.copy(launcher, desktop / "LogSentinel.command")
            print(f"  ✓ Launcher criado no Desktop")
        
        return True
        
    except Exception as e:
        print(f"  ⚠ Erro ao criar atalho: {e}")
        return True


def verify_installation():
    """Verifica se a instalação foi bem sucedida."""
    print("\n[5/5] A verificar instalação...")
    
    try:
        import customtkinter
        from PIL import Image
        print("  ✓ customtkinter OK")
        print("  ✓ pillow OK")
        
        # Verificar módulos internos
        sys.path.insert(0, str(Path(__file__).parent / "src"))
        from core.database import DatabaseManager
        from core.engine import DetectionEngine
        print("  ✓ Módulos internos OK")
        
        return True
        
    except ImportError as e:
        print(f"  ✗ Erro de importação: {e}")
        return False


def main():
    """Função principal do instalador."""
    print_banner()
    
    steps = [
        ("Verificação Python", check_python),
        ("Instalação de dependências", install_dependencies),
        ("Criação de diretórios", create_directories),
        ("Criação de atalho", create_desktop_shortcut),
        ("Verificação final", verify_installation),
    ]
    
    failed = False
    for name, func in steps:
        if not func():
            failed = True
            break
    
    print("\n" + "="*60)
    
    if failed:
        print("\n⚠️  Instalação incompleta!")
        print("   Verifique os erros acima e tente novamente.\n")
        return 1
    else:
        print("\n✅ Instalação concluída com sucesso!")
        print("\n   Para iniciar o Log Sentinel:")
        print("   - Clique no atalho no Desktop")
        print("   - Ou execute: python main.py\n")
        return 0


if __name__ == "__main__":
    sys.exit(main())
