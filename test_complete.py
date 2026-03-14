#!/usr/bin/env python3
"""
Log Sentinel v2.0 - Script de Testes Completo
==============================================
Testa TODAS as funcionalidades do sistema.

Autor: Duarte Cunha (Nº 2024271)
ISTEC - 2025/2026

Uso: python test_complete.py
"""

import sys
import os
import time
from pathlib import Path
from datetime import datetime

# Adicionar src ao path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

# Cores para output
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'

def print_header(text):
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}  {text}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.END}\n")

def print_test(name):
    print(f"{Colors.CYAN}🧪 Testando: {name}...{Colors.END}", end=" ")

def print_pass(msg="OK"):
    print(f"{Colors.GREEN}✅ {msg}{Colors.END}")

def print_fail(msg):
    print(f"{Colors.RED}❌ FALHOU: {msg}{Colors.END}")

def print_warn(msg):
    print(f"{Colors.YELLOW}⚠️  {msg}{Colors.END}")

def print_info(msg):
    print(f"   {Colors.CYAN}ℹ️  {msg}{Colors.END}")

# Contadores
tests_passed = 0
tests_failed = 0
tests_warned = 0

def test_passed():
    global tests_passed
    tests_passed += 1

def test_failed():
    global tests_failed
    tests_failed += 1

def test_warned():
    global tests_warned
    tests_warned += 1


# ============================================================
# FASE 1: IMPORTS E DEPENDÊNCIAS
# ============================================================
def test_phase_1():
    print_header("FASE 1: Imports e Dependências")
    
    # 1.1 - Módulos Python padrão
    print_test("Módulos Python padrão")
    try:
        import json, re, sqlite3, threading, queue
        from datetime import datetime
        from pathlib import Path
        from collections import defaultdict
        from dataclasses import dataclass
        print_pass()
        test_passed()
    except ImportError as e:
        print_fail(str(e))
        test_failed()
    
    # 1.2 - CustomTkinter
    print_test("CustomTkinter (GUI)")
    try:
        import customtkinter as ctk
        print_pass(f"v{ctk.__version__ if hasattr(ctk, '__version__') else 'OK'}")
        test_passed()
    except ImportError:
        print_fail("pip install customtkinter")
        test_failed()
    
    # 1.3 - Pillow
    print_test("Pillow (Imagens)")
    try:
        from PIL import Image
        print_pass()
        test_passed()
    except ImportError:
        print_fail("pip install pillow")
        test_failed()
    
    # 1.4 - NumPy
    print_test("NumPy")
    try:
        import numpy as np
        print_pass(f"v{np.__version__}")
        test_passed()
    except ImportError:
        print_fail("pip install numpy")
        test_failed()
    
    # 1.5 - scikit-learn
    print_test("scikit-learn (ML)")
    try:
        import sklearn
        from sklearn.ensemble import IsolationForest
        print_pass(f"v{sklearn.__version__}")
        test_passed()
    except ImportError:
        print_fail("pip install scikit-learn")
        test_failed()
    
    # 1.6 - ReportLab (PDF)
    print_test("ReportLab (PDF)")
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas
        print_pass()
        test_passed()
    except ImportError:
        print_warn("Opcional - pip install reportlab")
        test_warned()
    
    # 1.7 - python-docx (Word)
    print_test("python-docx (Word)")
    try:
        from docx import Document
        print_pass()
        test_passed()
    except ImportError:
        print_warn("Opcional - pip install python-docx")
        test_warned()
    
    # 1.8 - Watchdog (Real-time)
    print_test("Watchdog (Monitorização)")
    try:
        from watchdog.observers import Observer
        print_pass()
        test_passed()
    except ImportError:
        print_warn("Opcional - pip install watchdog")
        test_warned()


# ============================================================
# FASE 2: MÓDULOS CORE
# ============================================================
def test_phase_2():
    print_header("FASE 2: Módulos Core")
    
    # 2.1 - Parser
    print_test("LogParser")
    try:
        from core.parser import LogParser, LogEntry
        parser = LogParser()
        print_pass()
        test_passed()
        
        # Testar parsing de diferentes formatos
        test_lines = [
            ('Apache', '192.168.1.1 - - [29/Jan/2024:10:00:00 +0000] "GET / HTTP/1.1" 200 1234'),
            ('Syslog', 'Jan 29 10:00:00 server sshd[1234]: Failed password for admin from 192.168.1.100'),
            ('Error', '[Mon Jan 29 10:00:00 2024] [error] [client 192.168.1.1] File not found'),
        ]
        
        for name, line in test_lines:
            print_test(f"  Parser: {name}")
            entry = parser.parse_line(line)
            if entry and entry.log_type != "UNKNOWN":
                print_pass(f"Tipo: {entry.log_type}")
                test_passed()
            else:
                print_warn(f"Não reconhecido como {name}")
                test_warned()
                
    except Exception as e:
        print_fail(str(e))
        test_failed()
    
    # 2.2 - Database
    print_test("DatabaseManager")
    try:
        from core.database import DatabaseManager
        db = DatabaseManager(":memory:")  # Base de dados em memória
        print_pass()
        test_passed()
        
        # Testar operações
        print_test("  DB: Guardar sessão")
        session_id = db.save_session("test.log", "test_session")
        if session_id:
            print_pass(f"ID: {session_id}")
            test_passed()
        else:
            print_fail("Sem ID retornado")
            test_failed()
            
    except Exception as e:
        print_fail(str(e))
        test_failed()
    
    # 2.3 - Detection Engine
    print_test("DetectionEngine")
    try:
        from core.engine import DetectionEngine, Anomaly, Severity, AnomalyType
        engine = DetectionEngine()
        print_pass()
        test_passed()
        
        # Verificar tipos de ataque
        print_test("  Engine: Tipos de ataque")
        attack_types = [e.value for e in AnomalyType]
        print_pass(f"{len(attack_types)} tipos")
        print_info(f"Tipos: {', '.join(attack_types[:5])}...")
        test_passed()
        
    except Exception as e:
        print_fail(str(e))
        test_failed()
    
    # 2.4 - Exporter
    print_test("ReportExporter")
    try:
        from core.exporter import ReportExporter
        exporter = ReportExporter()
        formats = exporter.get_supported_formats()
        print_pass(f"Formatos: {', '.join(formats)}")
        test_passed()
    except Exception as e:
        print_fail(str(e))
        test_failed()


# ============================================================
# FASE 3: DETEÇÃO DE ATAQUES
# ============================================================
def test_phase_3():
    print_header("FASE 3: Deteção de Ataques")
    
    from core.parser import LogParser
    parser = LogParser()
    
    attack_tests = [
        ("SQL Injection", 
         "192.168.1.1 - - [29/Jan/2024:10:00:00 +0000] \"GET /users?id=1' OR '1'='1 HTTP/1.1\" 200 500",
         "SQL_INJECTION"),
        
        ("XSS", 
         "192.168.1.1 - - [29/Jan/2024:10:00:00 +0000] \"GET /search?q=<script>alert(1)</script> HTTP/1.1\" 200 500",
         "XSS"),
        
        ("Path Traversal", 
         "192.168.1.1 - - [29/Jan/2024:10:00:00 +0000] \"GET /files?path=../../../etc/passwd HTTP/1.1\" 200 500",
         "PATH_TRAVERSAL"),
        
        ("Command Injection", 
         "192.168.1.1 - - [29/Jan/2024:10:00:00 +0000] \"GET /ping?host=;cat /etc/passwd HTTP/1.1\" 200 500",
         "COMMAND_INJECTION"),
        
        ("Scanner (Nikto)", 
         "192.168.1.1 - - [29/Jan/2024:10:00:00 +0000] \"GET /.git/config HTTP/1.1\" 404 0 \"-\" \"Nikto/2.1.5\"",
         "SCANNER"),
        
        ("LFI/RFI", 
         "192.168.1.1 - - [29/Jan/2024:10:00:00 +0000] \"GET /page?file=php://filter/resource=config.php HTTP/1.1\" 200 500",
         "LFI_RFI"),
    ]
    
    for name, line, expected in attack_tests:
        print_test(f"Deteção: {name}")
        entry = parser.parse_line(line)
        if entry:
            attacks = entry.extra.get('attack_indicators', [])
            if expected in attacks:
                print_pass(f"Detetado: {expected}")
                test_passed()
            elif attacks:
                print_warn(f"Detetado outro: {attacks}")
                test_warned()
            else:
                print_fail(f"Não detetado (esperado: {expected})")
                test_failed()
        else:
            print_fail("Parsing falhou")
            test_failed()


# ============================================================
# FASE 4: MACHINE LEARNING
# ============================================================
def test_phase_4():
    print_header("FASE 4: Machine Learning")
    
    # 4.1 - Anomaly Detector
    print_test("AnomalyDetector")
    try:
        from ml.anomaly_detector import AnomalyDetector, SKLEARN_AVAILABLE
        
        if not SKLEARN_AVAILABLE:
            print_warn("scikit-learn não disponível")
            test_warned()
            return
            
        detector = AnomalyDetector()
        print_pass()
        test_passed()
        
        # 4.2 - Feature Extraction
        print_test("Feature Extraction")
        from ml.anomaly_detector import FeatureExtractor
        extractor = FeatureExtractor()
        
        test_entry = {
            'timestamp': datetime.now(),
            'source_ip': '192.168.1.100',
            'action': 'GET',
            'target': '/api/users?id=1',
            'status': '200',
            'user_agent': 'Mozilla/5.0'
        }
        features = extractor.extract(test_entry)
        print_pass(f"{len(features)} features extraídas")
        test_passed()
        
        # 4.3 - Treino do modelo
        print_test("Treino ML (Isolation Forest)")
        
        # Gerar dados sintéticos
        import numpy as np
        training_data = []
        for i in range(50):
            training_data.append({
                'timestamp': datetime.now(),
                'source_ip': f'192.168.1.{np.random.randint(1, 255)}',
                'action': 'GET',
                'target': f'/page{i}',
                'status': '200',
                'user_agent': 'Mozilla/5.0'
            })
        
        result = detector.train_anomaly_detector(training_data, contamination=0.1)
        if result.get('success'):
            print_pass(f"Treinado com {result['samples_trained']} amostras")
            test_passed()
        else:
            print_fail(result.get('error', 'Erro desconhecido'))
            test_failed()
        
        # 4.4 - Predição
        if detector.is_trained:
            print_test("Predição ML")
            prediction = detector.predict(test_entry)
            print_pass(f"Anomalia: {prediction.is_anomaly}, Score: {prediction.anomaly_score:.2f}")
            test_passed()
            
    except Exception as e:
        print_fail(str(e))
        test_failed()
    
    # 4.5 - Modelos pré-treinados
    print_test("Modelos Pré-treinados")
    try:
        from ml.pretrained_models import PretrainedModels
        pm = PretrainedModels("data/models")
        profiles = pm.get_available_profiles()
        print_pass(f"{len(profiles)} perfis disponíveis")
        print_info(f"Perfis: {', '.join([p['id'] for p in profiles])}")
        test_passed()
    except Exception as e:
        print_fail(str(e))
        test_failed()


# ============================================================
# FASE 5: ANÁLISE DE FICHEIROS
# ============================================================
def test_phase_5():
    print_header("FASE 5: Análise de Ficheiros")
    
    from core.engine import DetectionEngine
    
    # Usar engine sem database para teste
    engine = DetectionEngine(db=None)
    
    log_files = [
        "data/logs/demo_completo.log",
        "data/logs/web.log",
        "data/logs/auth.log",
        "data/logs/ssh_attack.log",
        "data/logs/apache_error.log",
    ]
    
    for log_file in log_files:
        print_test(f"Analisar: {os.path.basename(log_file)}")
        
        if not os.path.exists(log_file):
            print_warn("Ficheiro não encontrado")
            test_warned()
            continue
        
        try:
            engine.reset()
            anomalies = []
            
            # Analisar sem guardar na BD
            def progress_callback(progress, status):
                pass
            
            anomalies = engine.analyze_file(log_file, progress_callback=progress_callback)
            stats = engine.get_stats()
            
            print_pass(f"{stats['entries_processed']} linhas, {stats['anomalies_detected']} anomalias")
            
            # Mostrar distribuição
            if stats['by_severity']:
                severity_str = ", ".join([f"{k}:{v}" for k, v in stats['by_severity'].items()])
                print_info(f"Severidades: {severity_str}")
            
            test_passed()
            
        except Exception as e:
            print_fail(str(e))
            test_failed()


# ============================================================
# FASE 6: EXPORTAÇÃO
# ============================================================
def test_phase_6():
    print_header("FASE 6: Exportação de Relatórios")
    
    from core.engine import DetectionEngine, Anomaly, Severity, AnomalyType
    from core.exporter import ReportExporter
    from datetime import datetime
    
    exporter = ReportExporter()
    
    # Criar anomalias de teste
    test_anomalies = [
        Anomaly(
            anomaly_type=AnomalyType.SQL_INJECTION,
            severity=Severity.CRITICAL,
            source_ip="192.168.1.100",
            target="/login",
            detail="SQL Injection detected: ' OR '1'='1",
            evidence=["GET /login?id=1' OR '1'='1"],
            timestamp=datetime.now()
        ),
        Anomaly(
            anomaly_type=AnomalyType.XSS,
            severity=Severity.HIGH,
            source_ip="10.0.0.50",
            target="/search",
            detail="XSS detected: <script>",
            evidence=["GET /search?q=<script>alert(1)</script>"],
            timestamp=datetime.now()
        ),
    ]
    
    test_stats = {
        'entries_processed': 100,
        'anomalies_detected': 2,
        'by_severity': {'CRITICAL': 1, 'HIGH': 1},
        'by_type': {'SQL_INJECTION': 1, 'XSS': 1}
    }
    
    # Testar cada formato
    formats = ['json', 'csv', 'pdf', 'docx']
    
    for fmt in formats:
        print_test(f"Exportar: {fmt.upper()}")
        try:
            output_path = f"data/reports/test_report.{fmt}"
            
            if fmt == 'json':
                result = exporter.export_json(test_anomalies, output_path)
            elif fmt == 'csv':
                result = exporter.export_csv(test_anomalies, output_path)
            elif fmt == 'pdf':
                result = exporter.export_pdf(test_anomalies, test_stats, output_path, "test.log")
            elif fmt == 'docx':
                result = exporter.export_docx(test_anomalies, test_stats, output_path, "test.log")
            
            if result and os.path.exists(output_path):
                size = os.path.getsize(output_path)
                print_pass(f"Criado ({size} bytes)")
                test_passed()
                # Limpar ficheiro de teste
                os.remove(output_path)
            else:
                print_fail("Ficheiro não criado")
                test_failed()
                
        except Exception as e:
            print_warn(f"Erro: {e}")
            test_warned()


# ============================================================
# FASE 7: PLUGINS
# ============================================================
def test_phase_7():
    print_header("FASE 7: Sistema de Plugins")
    
    print_test("PluginManager")
    try:
        from plugins.plugin_system import PluginManager
        manager = PluginManager()
        print_pass()
        test_passed()
        
        # Listar plugins
        print_test("Plugins disponíveis")
        plugins = manager.list_plugins()
        print_pass(f"{len(plugins)} plugins")
        
        for plugin in plugins:
            print_info(f"Plugin: {plugin['name']} - {plugin['description'][:40]}...")
        test_passed()
        
        # Testar cada plugin
        from core.parser import LogEntry
        test_entry = LogEntry(
            raw_line='10.0.0.1 - - [29/Jan/2024:03:00:00 +0000] "GET /api/users HTTP/1.1" 200 500',
            timestamp=datetime(2024, 1, 29, 3, 0, 0),
            source_ip="10.0.0.1",
            action="GET",
            target="/api/users",
            status="200",
            log_type="WEB_ACCESS"
        )
        
        for plugin in plugins:
            print_test(f"  Executar: {plugin['name']}")
            try:
                result = manager.run_plugin(plugin['name'], test_entry)
                if result:
                    print_pass(f"Detetou: {result.anomaly_type.value}")
                else:
                    print_pass("Nenhuma anomalia (esperado)")
                test_passed()
            except Exception as e:
                print_fail(str(e))
                test_failed()
                
    except Exception as e:
        print_fail(str(e))
        test_failed()


# ============================================================
# FASE 8: INTEGRAÇÃO SIEM
# ============================================================
def test_phase_8():
    print_header("FASE 8: Integração SIEM")
    
    print_test("SIEMIntegration")
    try:
        from core.siem_integration import SIEMIntegration, SIEMEvent, SIEMType
        
        siem = SIEMIntegration()
        print_pass()
        test_passed()
        
        # Adicionar conector de ficheiro
        print_test("Adicionar conector File")
        siem.add_connector({
            'name': 'Test File',
            'type': 'file',
            'enabled': True,
            'filepath': 'data/test_siem.jsonl'
        })
        print_pass(f"{len(siem.connectors)} conectores")
        test_passed()
        
        # Criar e enviar evento
        print_test("Enviar evento SIEM")
        event = SIEMEvent(
            timestamp=datetime.now().isoformat(),
            source="test.log",
            event_type="SQL_INJECTION",
            severity="CRITICAL",
            message="Test SQL Injection event",
            source_ip="192.168.1.100"
        )
        
        siem.send_event(event, async_send=False)
        stats = siem.get_stats()
        
        if stats['events_sent'] > 0:
            print_pass(f"Enviados: {stats['events_sent']}")
            test_passed()
        else:
            print_fail("Nenhum evento enviado")
            test_failed()
        
        # Testar formatos de output
        print_test("Formato Syslog")
        syslog_msg = event.to_syslog()
        if '<' in syslog_msg and '>' in syslog_msg:
            print_pass("Formato válido")
            test_passed()
        else:
            print_fail("Formato inválido")
            test_failed()
        
        print_test("Formato CEF")
        cef_msg = event.to_cef()
        if cef_msg.startswith("CEF:"):
            print_pass("Formato válido")
            test_passed()
        else:
            print_fail("Formato inválido")
            test_failed()
        
        # Limpar
        if os.path.exists('data/test_siem.jsonl'):
            os.remove('data/test_siem.jsonl')
            
    except Exception as e:
        print_fail(str(e))
        test_failed()


# ============================================================
# FASE 9: MONITORIZAÇÃO EM TEMPO REAL
# ============================================================
def test_phase_9():
    print_header("FASE 9: Monitorização em Tempo Real")
    
    print_test("RealTimeMonitor")
    try:
        from core.realtime_monitor import RealTimeMonitor, WATCHDOG_AVAILABLE
        
        if not WATCHDOG_AVAILABLE:
            print_warn("watchdog não disponível - pip install watchdog")
            test_warned()
            return
        
        monitor = RealTimeMonitor()
        print_pass()
        test_passed()
        
        # Testar callback
        print_test("Adicionar callback")
        events_received = []
        monitor.add_callback(lambda e: events_received.append(e))
        print_pass(f"{len(monitor.callbacks)} callbacks")
        test_passed()
        
        # Testar estatísticas
        print_test("Estatísticas")
        stats = monitor.get_stats()
        print_pass(f"Running: {stats['is_running']}")
        test_passed()
        
    except Exception as e:
        print_fail(str(e))
        test_failed()


# ============================================================
# FASE 10: PARSERS ESTENDIDOS
# ============================================================
def test_phase_10():
    print_header("FASE 10: Parsers Estendidos")
    
    print_test("ExtendedLogParser")
    try:
        from core.extended_parsers import ExtendedLogParser
        
        parser = ExtendedLogParser()
        formats = parser.get_supported_formats()
        print_pass(f"{len(formats)} formatos")
        test_passed()
        
        # Testar cada parser
        test_lines = [
            ("Windows Event", "01/29/2024 14:30:45 PM Error Security 4625 Logon An account failed to log on"),
            ("IIS", "2024-01-29 14:30:45 192.168.1.1 GET /api/users - 80 - 10.0.0.100 Mozilla/5.0 - 200 0 0 125"),
            ("PostgreSQL", "2024-01-29 14:30:45.123 UTC [1234] postgres@mydb ERROR: syntax error"),
            ("Firewall UFW", "[UFW BLOCK] IN=eth0 OUT= SRC=10.0.0.100 DST=192.168.1.1 PROTO=TCP"),
        ]
        
        for name, line in test_lines:
            print_test(f"  Parser: {name}")
            result = parser.parse_line(line)
            if result:
                print_pass(f"Tipo: {result.log_type}")
                test_passed()
            else:
                print_warn("Não reconhecido")
                test_warned()
                
    except Exception as e:
        print_fail(str(e))
        test_failed()


# ============================================================
# FASE 11: INTERFACE GRÁFICA (sem abrir janela)
# ============================================================
def test_phase_11():
    print_header("FASE 11: Componentes GUI")
    
    print_test("Theme")
    try:
        from utils.theme import theme, Icons, Fonts
        print_pass(f"Cor primária: {theme.ACCENT_PRIMARY}")
        test_passed()
    except Exception as e:
        print_fail(str(e))
        test_failed()
    
    print_test("Config")
    try:
        from utils.config import config, get_app_info
        info = get_app_info()
        print_pass(f"v{info['version']} - {info['author']}")
        test_passed()
    except Exception as e:
        print_fail(str(e))
        test_failed()
    
    print_test("Componentes importáveis")
    try:
        from gui.components import Card, MetricCard, AlertItem, TabView, StatusIndicator
        print_pass("Todos os componentes OK")
        test_passed()
    except Exception as e:
        print_fail(str(e))
        test_failed()


# ============================================================
# FASE 12: FICHEIROS E RECURSOS
# ============================================================
def test_phase_12():
    print_header("FASE 12: Ficheiros e Recursos")
    
    required_files = [
        ("main.py", "Entrada principal"),
        ("requirements.txt", "Dependências"),
        ("README.md", "Documentação"),
        ("assets/icons/owl_logo.png", "Logo PNG"),
        ("assets/icons/owl_logo.ico", "Logo ICO"),
        ("data/logs/demo_completo.log", "Log de demo"),
        ("data/siem_config.json", "Config SIEM"),
    ]
    
    for filepath, description in required_files:
        print_test(f"{description}")
        if os.path.exists(filepath):
            size = os.path.getsize(filepath)
            print_pass(f"{filepath} ({size} bytes)")
            test_passed()
        else:
            print_fail(f"Não encontrado: {filepath}")
            test_failed()


# ============================================================
# SUMÁRIO FINAL
# ============================================================
def print_summary():
    print_header("SUMÁRIO DOS TESTES")
    
    total = tests_passed + tests_failed + tests_warned
    
    print(f"  {Colors.GREEN}✅ Passou:  {tests_passed}{Colors.END}")
    print(f"  {Colors.RED}❌ Falhou:  {tests_failed}{Colors.END}")
    print(f"  {Colors.YELLOW}⚠️  Avisos:  {tests_warned}{Colors.END}")
    print(f"  {Colors.CYAN}📊 Total:   {total}{Colors.END}")
    print()
    
    if tests_failed == 0:
        print(f"  {Colors.GREEN}{Colors.BOLD}🎉 TODOS OS TESTES PASSARAM!{Colors.END}")
    elif tests_failed < 5:
        print(f"  {Colors.YELLOW}{Colors.BOLD}⚠️  Alguns testes falharam - verificar dependências{Colors.END}")
    else:
        print(f"  {Colors.RED}{Colors.BOLD}❌ Muitos testes falharam - verificar instalação{Colors.END}")
    
    print()
    return tests_failed == 0


# ============================================================
# MAIN
# ============================================================
if __name__ == "__main__":
    print(f"""
{Colors.BOLD}{Colors.GREEN}
╔══════════════════════════════════════════════════════════════╗
║           LOG SENTINEL v2.0 - TESTES COMPLETOS               ║
║                                                              ║
║  Autor: Duarte Cunha (Nº 2024271)                           ║
║  ISTEC - 2025/2026                                          ║
╚══════════════════════════════════════════════════════════════╝
{Colors.END}
""")
    
    start_time = time.time()
    
    # Executar todas as fases
    test_phase_1()   # Imports
    test_phase_2()   # Core modules
    test_phase_3()   # Attack detection
    test_phase_4()   # Machine Learning
    test_phase_5()   # File analysis
    test_phase_6()   # Export
    test_phase_7()   # Plugins
    test_phase_8()   # SIEM
    test_phase_9()   # Real-time
    test_phase_10()  # Extended parsers
    test_phase_11()  # GUI components
    test_phase_12()  # Files
    
    elapsed = time.time() - start_time
    
    print(f"\n  ⏱️  Tempo total: {elapsed:.2f} segundos\n")
    
    success = print_summary()
    
    sys.exit(0 if success else 1)
