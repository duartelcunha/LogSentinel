# -*- mode: python ; coding: utf-8 -*-
"""
Log Sentinel v2.0 - PyInstaller Spec File
==========================================
Configuração para criar executável standalone.

Author: Duarte Cunha (Nº 2024271)
ISTEC - 2025/2026

Uso:
    pyinstaller LogSentinel.spec
"""

import os
import sys
from pathlib import Path

block_cipher = None

# Diretório base
BASE_DIR = Path(SPECPATH)

# Determinar separador de dados
separator = ';' if sys.platform == 'win32' else ':'

# Análise de dependências
a = Analysis(
    [str(BASE_DIR / 'main.py')],
    pathex=[str(BASE_DIR), str(BASE_DIR / 'src')],
    binaries=[],
    datas=[
        (str(BASE_DIR / 'assets'), 'assets'),
        (str(BASE_DIR / 'data' / 'logs'), 'data/logs'),
    ],
    hiddenimports=[
        'customtkinter',
        'PIL',
        'PIL.Image',
        'PIL.ImageTk',
        'sklearn',
        'sklearn.ensemble',
        'sklearn.ensemble._forest',
        'sklearn.ensemble._iforest',
        'sklearn.preprocessing',
        'sklearn.preprocessing._data',
        'sklearn.model_selection',
        'sklearn.model_selection._split',
        'sklearn.utils._cython_blas',
        'sklearn.neighbors._typedefs',
        'sklearn.neighbors._quad_tree',
        'sklearn.tree._utils',
        'numpy',
        'pandas',
        'joblib',
        'reportlab',
        'reportlab.lib',
        'reportlab.lib.pagesizes',
        'reportlab.lib.colors',
        'reportlab.lib.styles',
        'reportlab.platypus',
        'reportlab.pdfgen',
        'docx',
        'docx.shared',
        'openpyxl',
        'plyer',
        'plyer.platforms',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'matplotlib',
        'PyQt5',
        'PyQt6',
        'PySide2',
        'PySide6',
        'tkinter.test',
        'unittest',
        'pytest',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

# Adicionar customtkinter data files
import customtkinter
ctk_path = Path(customtkinter.__file__).parent
a.datas += [(str(p.relative_to(ctk_path.parent)), str(p), 'DATA') 
            for p in ctk_path.rglob('*') if p.is_file()]

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='LogSentinel',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # Sem consola (GUI only)
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(BASE_DIR / 'assets' / 'icons' / 'owl_logo.ico') if (BASE_DIR / 'assets' / 'icons' / 'owl_logo.ico').exists() else None,
)
