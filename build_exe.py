#!/usr/bin/env python3
"""
Log Sentinel v2.0 - Build Script
================================
Cria executável standalone para Windows/Linux/macOS.

Uso:
    python build_exe.py

Requisitos:
    pip install pyinstaller

Author: Duarte Cunha (Nº 2024271)
ISTEC - 2025/2026
"""

import subprocess
import sys
import os
import shutil
from pathlib import Path

# Cores para output
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'

def print_header(text):
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.CYAN}  {text}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.END}\n")

def print_step(text):
    print(f"{Colors.YELLOW}→ {text}{Colors.END}")

def print_success(text):
    print(f"{Colors.GREEN}✓ {text}{Colors.END}")

def print_error(text):
    print(f"{Colors.RED}✗ {text}{Colors.END}")

def check_pyinstaller():
    """Verifica se PyInstaller está instalado."""
    try:
        import PyInstaller
        print_success(f"PyInstaller {PyInstaller.__version__} encontrado")
        return True
    except ImportError:
        print_error("PyInstaller não encontrado")
        print_step("A instalar PyInstaller...")
        subprocess.run([sys.executable, "-m", "pip", "install", "pyinstaller", "-q"])
        return True

def clean_build():
    """Limpa builds anteriores."""
    print_step("A limpar builds anteriores...")
    dirs_to_clean = ['build', 'dist', '__pycache__']
    for d in dirs_to_clean:
        if os.path.exists(d):
            shutil.rmtree(d)
    
    # Remover .spec se existir (vamos usar o nosso)
    for f in Path('.').glob('*.spec'):
        if f.name != 'LogSentinel.spec':
            f.unlink()
    
    print_success("Limpeza concluída")

def build_executable():
    """Cria o executável."""
    print_step("A criar executável...")
    
    # Verificar se estamos no diretório correto
    if not os.path.exists('main.py'):
        print_error("Erro: Execute este script na pasta LogSentinel_v2")
        return False
    
    # Usar spec file se existir, senão criar comando
    if os.path.exists('LogSentinel.spec'):
        cmd = [sys.executable, "-m", "PyInstaller", "LogSentinel.spec", "--noconfirm"]
    else:
        # Criar comando PyInstaller
        cmd = [
            sys.executable, "-m", "PyInstaller",
            "--name=LogSentinel",
            "--onefile",
            "--windowed",
            "--add-data=assets:assets",
            "--add-data=data/logs:data/logs",
            "--hidden-import=customtkinter",
            "--hidden-import=PIL",
            "--hidden-import=sklearn",
            "--hidden-import=sklearn.ensemble",
            "--hidden-import=numpy",
            "--hidden-import=pandas",
            "--hidden-import=joblib",
            "--hidden-import=reportlab",
            "--hidden-import=docx",
            "--hidden-import=openpyxl",
            "--collect-all=customtkinter",
            "--noconfirm",
            "main.py"
        ]
        
        # Adicionar ícone se existir
        icon_path = Path("assets/icons/owl_logo.ico")
        if icon_path.exists():
            cmd.insert(-1, f"--icon={icon_path}")
    
    print(f"  Comando: {' '.join(cmd[:5])}...")
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode == 0:
        print_success("Executável criado com sucesso!")
        return True
    else:
        print_error("Erro ao criar executável:")
        print(result.stderr[-500:] if len(result.stderr) > 500 else result.stderr)
        return False

def copy_resources():
    """Copia recursos adicionais para a pasta dist."""
    print_step("A copiar recursos...")
    
    dist_dir = Path("dist")
    if not dist_dir.exists():
        print_error("Pasta dist não encontrada")
        return
    
    # Copiar logs de exemplo
    logs_src = Path("data/logs")
    logs_dst = dist_dir / "data" / "logs"
    if logs_src.exists():
        logs_dst.mkdir(parents=True, exist_ok=True)
        for log in logs_src.glob("*.log"):
            shutil.copy(log, logs_dst)
        print_success(f"Logs de exemplo copiados para {logs_dst}")
    
    # Copiar README
    if Path("README.md").exists():
        shutil.copy("README.md", dist_dir)
        print_success("README copiado")
    
    # Criar pasta para relatórios
    (dist_dir / "data" / "reports").mkdir(parents=True, exist_ok=True)
    (dist_dir / "data" / "models").mkdir(parents=True, exist_ok=True)

def main():
    print_header("🦉 LOG SENTINEL - BUILD EXECUTÁVEL")
    
    # Verificar PyInstaller
    if not check_pyinstaller():
        return 1
    
    # Limpar
    clean_build()
    
    # Build
    if not build_executable():
        return 1
    
    # Copiar recursos
    copy_resources()
    
    # Resultado
    print_header("BUILD COMPLETO")
    
    exe_name = "LogSentinel.exe" if sys.platform == "win32" else "LogSentinel"
    exe_path = Path("dist") / exe_name
    
    if exe_path.exists():
        size_mb = exe_path.stat().st_size / (1024 * 1024)
        print_success(f"Executável: {exe_path}")
        print_success(f"Tamanho: {size_mb:.1f} MB")
        print(f"\n{Colors.GREEN}Para executar:{Colors.END}")
        print(f"  cd dist")
        print(f"  ./{exe_name}")
    else:
        # Verificar se foi criado como pasta (onedir)
        exe_folder = Path("dist/LogSentinel")
        if exe_folder.exists():
            print_success(f"Executável criado em: {exe_folder}")
            print(f"\n{Colors.GREEN}Para executar:{Colors.END}")
            print(f"  cd dist/LogSentinel")
            print(f"  ./LogSentinel")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
