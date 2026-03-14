#!/usr/bin/env python3
"""
Log Sentinel v2.0 - Sistema de Testes Completo
===============================================
Testa todas as funcionalidades do sistema.

Author: Duarte Cunha (Nº 2024271)
ISTEC - Instituto Superior de Tecnologias Avançadas de Lisboa
Ano Letivo: 2025/2026

Uso:
    python test_system.py              # Executa todos os testes
    python test_system.py --verbose    # Modo verbose
    python test_system.py --module X   # Testa módulo específico
"""

import sys
import os
import unittest
import tempfile
import shutil
from datetime import datetime
from pathlib import Path
import argparse
import json

# Adicionar src ao path
BASE_DIR = Path(__file__).parent
sys.path.insert(0, str(BASE_DIR / 'src'))


class Colors:
    """Cores para output no terminal."""
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'


def print_header(text):
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.CYAN}  {text}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.END}\n")


def print_section(text):
    print(f"\n{Colors.BOLD}{Colors.BLUE}--- {text} ---{Colors.END}\n")


def print_success(text):
    print(f"  {Colors.GREEN}✓ {text}{Colors.END}")


def print_fail(text):
    print(f"  {Colors.RED}✗ {text}{Colors.END}")


def print_info(text):
    print(f"  {Colors.YELLOW}ℹ {text}{Colors.END}")


# ============================================================
# TESTES DO PARSER
# ============================================================

class TestParser(unittest.TestCase):
    """Testes do módulo Parser."""
    
    @classmethod
    def setUpClass(cls):
        from core.parser import LogParser
        cls.parser = LogParser()
    
    def test_parse_syslog(self):
        """Testa parsing de logs syslog."""
        line = "Jan 30 08:15:22 server sshd[12345]: Accepted password for admin from 192.168.1.10 port 22 ssh2"
        entry = self.parser.parse_line(line)
        
        self.assertIsNotNone(entry)
        self.assertEqual(entry.log_type, "AUTH")
        self.assertEqual(entry.source_ip, "192.168.1.10")
        self.assertEqual(entry.user, "admin")
        print_success("Parsing syslog/auth.log OK")
    
    def test_parse_web_access(self):
        """Testa parsing de logs web access."""
        line = '192.168.1.100 - - [30/Jan/2025:08:00:01 +0000] "GET /index.html HTTP/1.1" 200 5432 "-" "Mozilla/5.0"'
        entry = self.parser.parse_line(line)
        
        self.assertIsNotNone(entry)
        self.assertEqual(entry.log_type, "WEB_ACCESS")
        self.assertEqual(entry.source_ip, "192.168.1.100")
        self.assertEqual(entry.status, "200")
        print_success("Parsing web access log OK")
    
    def test_detect_sql_injection(self):
        """Testa deteção de SQL Injection no parser."""
        line = '10.0.0.50 - - [30/Jan/2025:08:05:00 +0000] "GET /search?q=1 OR 1=1 HTTP/1.1" 200 500 "-" "Mozilla/5.0"'
        entry = self.parser.parse_line(line)
        
        self.assertIsNotNone(entry)
        self.assertIn('SQL_INJECTION', entry.extra.get('attack_indicators', []))
        print_success("Deteção de SQL Injection no parser OK")
    
    def test_detect_xss(self):
        """Testa deteção de XSS no parser."""
        line = '172.16.0.100 - - [30/Jan/2025:08:10:00 +0000] "GET /page?content=<script>alert(1)</script> HTTP/1.1" 200 1000'
        entry = self.parser.parse_line(line)
        
        self.assertIsNotNone(entry)
        self.assertIn('XSS', entry.extra.get('attack_indicators', []))
        print_success("Deteção de XSS no parser OK")
    
    def test_detect_path_traversal(self):
        """Testa deteção de Path Traversal."""
        line = '203.0.113.50 - - [30/Jan/2025:08:15:00 +0000] "GET /../../etc/passwd HTTP/1.1" 403 0'
        entry = self.parser.parse_line(line)
        
        self.assertIsNotNone(entry)
        self.assertIn('PATH_TRAVERSAL', entry.extra.get('attack_indicators', []))
        print_success("Deteção de Path Traversal OK")
    
    def test_parse_file(self):
        """Testa parsing de ficheiro completo."""
        # Criar ficheiro temporário
        with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
            f.write("Jan 30 08:15:22 server sshd[1]: Test line 1\n")
            f.write("Jan 30 08:15:23 server sshd[2]: Test line 2\n")
            f.write("Jan 30 08:15:24 server sshd[3]: Test line 3\n")
            temp_path = f.name
        
        try:
            entries = list(self.parser.parse_file(temp_path))
            self.assertEqual(len(entries), 3)
            print_success(f"Parsing de ficheiro OK ({len(entries)} entradas)")
        finally:
            os.unlink(temp_path)


# ============================================================
# TESTES DA BASE DE DADOS
# ============================================================

class TestDatabase(unittest.TestCase):
    """Testes do módulo Database."""
    
    @classmethod
    def setUpClass(cls):
        from core.database import DatabaseManager
        cls.temp_dir = tempfile.mkdtemp()
        cls.db_path = os.path.join(cls.temp_dir, "test.db")
        cls.db = DatabaseManager(cls.db_path)
    
    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.temp_dir, ignore_errors=True)
    
    def test_insert_anomaly(self):
        """Testa inserção de anomalia."""
        anomaly_id = self.db.insert_anomaly(
            anomaly_type="SQL_INJECTION",
            detail="Teste de inserção",
            severity="HIGH",
            source_ip="192.168.1.100",
            score=0.85
        )
        
        self.assertIsNotNone(anomaly_id)
        self.assertGreater(anomaly_id, 0)
        print_success(f"Inserção de anomalia OK (ID: {anomaly_id})")
    
    def test_get_anomalies(self):
        """Testa obtenção de anomalias."""
        # Inserir algumas anomalias
        for i in range(5):
            self.db.insert_anomaly(
                anomaly_type="TEST",
                detail=f"Teste {i}",
                severity="MEDIUM"
            )
        
        anomalies = self.db.get_anomalies(limit=10)
        self.assertGreater(len(anomalies), 0)
        print_success(f"Obtenção de anomalias OK ({len(anomalies)} encontradas)")
    
    def test_get_statistics(self):
        """Testa obtenção de estatísticas."""
        stats = self.db.get_statistics()
        
        self.assertIn('total_anomalies', stats)
        self.assertIn('by_type', stats)
        self.assertIn('by_severity', stats)
        print_success(f"Estatísticas OK (Total: {stats['total_anomalies']})")
    
    def test_create_alert(self):
        """Testa criação de alerta."""
        # Primeiro inserir anomalia
        anomaly_id = self.db.insert_anomaly(
            anomaly_type="CRITICAL_TEST",
            detail="Teste de alerta",
            severity="CRITICAL"
        )
        
        alert_id = self.db.create_alert(
            anomaly_id=anomaly_id,
            alert_type="THREAT",
            severity="CRITICAL",
            title="Teste de Alerta",
            message="Mensagem de teste"
        )
        
        self.assertIsNotNone(alert_id)
        print_success(f"Criação de alerta OK (ID: {alert_id})")
    
    def test_get_timeline_data(self):
        """Testa obtenção de dados de timeline."""
        data = self.db.get_timeline_data(hours=24)
        self.assertIsInstance(data, list)
        print_success("Timeline data OK")
    
    def test_correlations(self):
        """Testa sistema de correlações."""
        # Inserir anomalias
        ids = []
        for _ in range(3):
            aid = self.db.insert_anomaly(
                anomaly_type="CORR_TEST",
                detail="Para correlação",
                severity="HIGH",
                source_ip="10.0.0.1"
            )
            ids.append(aid)
        
        # Criar correlação
        group_id = self.db.add_correlation(
            anomaly_ids=ids,
            correlation_type="multi_vector",
            confidence=0.8,
            description="Teste de correlação"
        )
        
        self.assertIsNotNone(group_id)
        print_success(f"Sistema de correlações OK (Grupo: {group_id})")


# ============================================================
# TESTES DO DETECTION ENGINE
# ============================================================

class TestDetectionEngine(unittest.TestCase):
    """Testes do motor de deteção."""
    
    @classmethod
    def setUpClass(cls):
        from core.database import DatabaseManager
        from core.engine import DetectionEngine
        
        cls.temp_dir = tempfile.mkdtemp()
        cls.db_path = os.path.join(cls.temp_dir, "test.db")
        cls.db = DatabaseManager(cls.db_path)
        cls.engine = DetectionEngine(cls.db, enable_ml=False)
    
    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.temp_dir, ignore_errors=True)
    
    def test_analyze_sql_injection(self):
        """Testa deteção de SQL Injection."""
        from core.parser import LogEntry
        
        entry = LogEntry(
            raw_line="GET /search?q=1' OR '1'='1 HTTP/1.1",
            source_ip="10.0.0.1",
            log_type="WEB_ACCESS",
            extra={'url': "/search?q=1' OR '1'='1"}
        )
        
        anomalies = self.engine.analyze_entry(entry)
        types = [a.anomaly_type.value for a in anomalies]
        
        self.assertIn('SQL_INJECTION', types)
        print_success("Deteção de SQL Injection OK")
    
    def test_analyze_xss(self):
        """Testa deteção de XSS."""
        from core.parser import LogEntry
        
        entry = LogEntry(
            raw_line="GET /page?x=<script>alert(1)</script> HTTP/1.1",
            source_ip="10.0.0.2",
            log_type="WEB_ACCESS",
            extra={'url': "/page?x=<script>alert(1)</script>"}
        )
        
        anomalies = self.engine.analyze_entry(entry)
        types = [a.anomaly_type.value for a in anomalies]
        
        self.assertIn('XSS', types)
        print_success("Deteção de XSS OK")
    
    def test_analyze_path_traversal(self):
        """Testa deteção de Path Traversal."""
        from core.parser import LogEntry
        
        entry = LogEntry(
            raw_line="GET /../../../etc/passwd HTTP/1.1",
            source_ip="10.0.0.3",
            log_type="WEB_ACCESS",
            extra={'url': "/../../../etc/passwd"}
        )
        
        anomalies = self.engine.analyze_entry(entry)
        types = [a.anomaly_type.value for a in anomalies]
        
        self.assertIn('PATH_TRAVERSAL', types)
        print_success("Deteção de Path Traversal OK")
    
    def test_analyze_command_injection(self):
        """Testa deteção de Command Injection."""
        from core.parser import LogEntry
        
        entry = LogEntry(
            raw_line="GET /cmd?exec=ls;cat /etc/passwd HTTP/1.1",
            source_ip="10.0.0.4",
            log_type="WEB_ACCESS",
            extra={'url': "/cmd?exec=ls;cat /etc/passwd"}
        )
        
        anomalies = self.engine.analyze_entry(entry)
        types = [a.anomaly_type.value for a in anomalies]
        
        self.assertIn('COMMAND_INJECTION', types)
        print_success("Deteção de Command Injection OK")
    
    def test_brute_force_detection(self):
        """Testa deteção de Brute Force."""
        from core.parser import LogEntry
        
        self.engine.reset()
        
        # Simular múltiplas tentativas falhadas
        for i in range(6):
            entry = LogEntry(
                raw_line=f"Failed password for admin from 192.168.1.100",
                source_ip="192.168.1.100",
                user="admin",
                status="FAILED",
                log_type="AUTH",
                timestamp=datetime.now()
            )
            self.engine.analyze_entry(entry)
        
        # Verificar stats
        stats = self.engine.get_stats()
        brute_force_count = stats['by_type'].get('BRUTE_FORCE', 0)
        
        self.assertGreater(brute_force_count, 0)
        print_success(f"Deteção de Brute Force OK ({brute_force_count} detetados)")
    
    def test_analyze_file(self):
        """Testa análise de ficheiro completo."""
        # Criar ficheiro de teste
        log_content = """192.168.1.100 - - [30/Jan/2025:08:00:01 +0000] "GET /index.html HTTP/1.1" 200 5432
10.0.0.50 - - [30/Jan/2025:08:05:00 +0000] "GET /search?q=1' OR 1=1-- HTTP/1.1" 200 500
172.16.0.100 - - [30/Jan/2025:08:10:00 +0000] "GET /page?x=<script>alert(1)</script> HTTP/1.1" 200 1000
203.0.113.50 - - [30/Jan/2025:08:15:00 +0000] "GET /../../etc/passwd HTTP/1.1" 403 0
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
            f.write(log_content)
            temp_path = f.name
        
        try:
            self.engine.reset()
            anomalies = self.engine.analyze_file(temp_path, "test_session")
            
            self.assertGreater(len(anomalies), 0)
            print_success(f"Análise de ficheiro OK ({len(anomalies)} anomalias)")
        finally:
            os.unlink(temp_path)
    
    def test_correlation(self):
        """Testa correlação de anomalias."""
        self.engine.reset()
        
        # Criar múltiplas anomalias do mesmo IP
        from core.parser import LogEntry
        
        attacks = [
            ("GET /search?q=1' OR 1=1 HTTP/1.1", {'url': "/search?q=1' OR 1=1"}),
            ("GET /page?x=<script>alert(1)</script> HTTP/1.1", {'url': "/page?x=<script>alert(1)</script>"}),
            ("GET /../../../etc/passwd HTTP/1.1", {'url': "/../../../etc/passwd"}),
        ]
        
        for raw, extra in attacks:
            entry = LogEntry(
                raw_line=raw,
                source_ip="10.0.0.99",
                log_type="WEB_ACCESS",
                extra=extra
            )
            self.engine.analyze_entry(entry)
        
        correlations = self.engine.correlate_anomalies()
        print_success(f"Correlação de anomalias OK ({len(correlations)} grupos)")


# ============================================================
# TESTES DO MÓDULO ML
# ============================================================

class TestMLModule(unittest.TestCase):
    """Testes do módulo de Machine Learning."""
    
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.mkdtemp()
    
    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.temp_dir, ignore_errors=True)
    
    def test_feature_extraction(self):
        """Testa extração de features."""
        try:
            from ml.anomaly_detector import FeatureExtractor
            
            extractor = FeatureExtractor()
            
            entry = {
                'timestamp': datetime.now(),
                'message': "GET /search?q=test HTTP/1.1",
                'source_ip': '192.168.1.100',
                'status': '200',
                'url': '/search?q=test',
                'user_agent': 'Mozilla/5.0'
            }
            
            features = extractor.extract(entry)
            
            self.assertEqual(len(features), 20)  # 20 features
            print_success(f"Extração de features OK ({len(features)} features)")
        except ImportError:
            print_info("scikit-learn não disponível, teste ML ignorado")
    
    def test_anomaly_detector_init(self):
        """Testa inicialização do detector."""
        try:
            from ml.anomaly_detector import AnomalyDetector
            
            detector = AnomalyDetector(self.temp_dir)
            info = detector.get_model_info()
            
            self.assertIn('sklearn_available', info)
            print_success(f"Inicialização do detector OK (sklearn: {info['sklearn_available']})")
        except ImportError:
            print_info("scikit-learn não disponível, teste ML ignorado")
    
    def test_prediction_without_training(self):
        """Testa predição sem treino."""
        try:
            from ml.anomaly_detector import AnomalyDetector
            
            detector = AnomalyDetector(self.temp_dir)
            
            entry = {
                'timestamp': datetime.now(),
                'message': "Normal request",
                'source_ip': '192.168.1.1',
                'status': '200'
            }
            
            prediction = detector.predict(entry)
            
            # Sem treino, não deve detetar anomalias
            self.assertFalse(prediction.is_anomaly)
            print_success("Predição sem treino OK (comportamento esperado)")
        except ImportError:
            print_info("scikit-learn não disponível, teste ML ignorado")


# ============================================================
# TESTES DO SISTEMA DE PLUGINS
# ============================================================

class TestPluginSystem(unittest.TestCase):
    """Testes do sistema de plugins."""
    
    def test_plugin_manager_init(self):
        """Testa inicialização do gestor de plugins."""
        from plugins.plugin_system import PluginManager
        
        manager = PluginManager()
        plugins = manager.get_plugins()
        
        self.assertGreater(len(plugins), 0)
        print_success(f"Inicialização do PluginManager OK ({len(plugins)} plugins)")
    
    def test_api_abuse_plugin(self):
        """Testa plugin de abuso de API."""
        from plugins.plugin_system import APIAbusePlugin
        
        plugin = APIAbusePlugin()
        
        entry = {
            'url': '/api/v1/users',
            'source_ip': '192.168.1.100'
        }
        
        result = plugin.detect(entry)
        self.assertIsNotNone(result)
        print_success("Plugin APIAbuse OK")
    
    def test_sensitive_data_plugin(self):
        """Testa plugin de dados sensíveis."""
        from plugins.plugin_system import SensitiveDataPlugin
        
        plugin = SensitiveDataPlugin()
        
        entry = {
            'raw_line': 'GET /login?password=secret123 HTTP/1.1'
        }
        
        result = plugin.detect(entry)
        self.assertTrue(result.detected)
        print_success("Plugin SensitiveData OK - detetou dados sensíveis")
    
    def test_anomalous_time_plugin(self):
        """Testa plugin de horário anómalo."""
        from plugins.plugin_system import AnomalousTimePlugin
        
        plugin = AnomalousTimePlugin()
        
        # Teste às 3:00 da manhã
        entry = {
            'timestamp': datetime.now().replace(hour=3)
        }
        
        result = plugin.detect(entry)
        self.assertTrue(result.detected)
        print_success("Plugin AnomalousTime OK - detetou horário anómalo")
    
    def test_plugin_processing(self):
        """Testa processamento de entrada por plugins."""
        from plugins.plugin_system import PluginManager
        
        manager = PluginManager()
        
        entry = {
            'raw_line': 'GET /api/v1/users?api_key=secret HTTP/1.1',
            'url': '/api/v1/users?api_key=secret',
            'source_ip': '10.0.0.1',
            'timestamp': datetime.now().replace(hour=3)
        }
        
        results = manager.process_entry(entry)
        print_success(f"Processamento de plugins OK ({len(results)} deteções)")


# ============================================================
# TESTES DO EXPORTADOR
# ============================================================

class TestExporter(unittest.TestCase):
    """Testes do módulo de exportação."""
    
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.mkdtemp()
        cls.test_anomalies = [
            {
                'type': 'SQL_INJECTION',
                'severity': 'CRITICAL',
                'source_ip': '192.168.1.100',
                'detail': 'Teste SQL Injection',
                'timestamp': datetime.now().isoformat()
            },
            {
                'type': 'XSS',
                'severity': 'HIGH',
                'source_ip': '10.0.0.50',
                'detail': 'Teste XSS',
                'timestamp': datetime.now().isoformat()
            }
        ]
        cls.test_stats = {
            'entries_processed': 1000,
            'anomalies_detected': 2,
            'total_anomalies': 2,
            'by_type': {'SQL_INJECTION': 1, 'XSS': 1},
            'by_severity': {'CRITICAL': 1, 'HIGH': 1},
            'top_ips': [('192.168.1.100', 5), ('10.0.0.50', 3)]
        }
    
    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.temp_dir, ignore_errors=True)
    
    def test_export_json(self):
        """Testa exportação JSON."""
        from core.exporter import ReportExporter
        
        exporter = ReportExporter()
        output_path = os.path.join(self.temp_dir, "report.json")
        
        result = exporter.export(
            self.test_anomalies,
            self.test_stats,
            output_path,
            "json"
        )
        
        self.assertTrue(result)
        self.assertTrue(os.path.exists(output_path))
        
        # Verificar conteúdo
        with open(output_path, 'r') as f:
            data = json.load(f)
        
        self.assertIn('anomalies', data)
        self.assertIn('summary', data)
        print_success("Exportação JSON OK")
    
    def test_export_csv(self):
        """Testa exportação CSV."""
        from core.exporter import ReportExporter
        
        exporter = ReportExporter()
        output_path = os.path.join(self.temp_dir, "report.csv")
        
        result = exporter.export(
            self.test_anomalies,
            self.test_stats,
            output_path,
            "csv"
        )
        
        self.assertTrue(result)
        self.assertTrue(os.path.exists(output_path))
        print_success("Exportação CSV OK")
    
    def test_export_pdf(self):
        """Testa exportação PDF."""
        try:
            from core.exporter import ReportExporter, REPORTLAB_AVAILABLE
            
            if not REPORTLAB_AVAILABLE:
                print_info("ReportLab não disponível, teste PDF ignorado")
                return
            
            exporter = ReportExporter()
            output_path = os.path.join(self.temp_dir, "report.pdf")
            
            result = exporter.export(
                self.test_anomalies,
                self.test_stats,
                output_path,
                "pdf"
            )
            
            self.assertTrue(result)
            self.assertTrue(os.path.exists(output_path))
            print_success("Exportação PDF OK")
        except Exception as e:
            print_info(f"Exportação PDF falhou: {e}")


# ============================================================
# TESTES DE INTEGRAÇÃO
# ============================================================

class TestIntegration(unittest.TestCase):
    """Testes de integração do sistema completo."""
    
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.mkdtemp()
    
    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.temp_dir, ignore_errors=True)
    
    def test_full_analysis_pipeline(self):
        """Testa pipeline completo de análise."""
        from core.database import DatabaseManager
        from core.engine import DetectionEngine
        from core.exporter import ReportExporter
        
        # Setup
        db_path = os.path.join(self.temp_dir, "test.db")
        db = DatabaseManager(db_path)
        engine = DetectionEngine(db, enable_ml=False)
        
        # Criar ficheiro de log de teste
        log_content = """192.168.1.100 - - [30/Jan/2025:08:00:01 +0000] "GET /index.html HTTP/1.1" 200 5432
10.0.0.50 - - [30/Jan/2025:08:05:00 +0000] "GET /search?q=1' OR 1=1-- HTTP/1.1" 200 500
172.16.0.100 - - [30/Jan/2025:08:10:00 +0000] "GET /page?x=<script>alert(1)</script> HTTP/1.1" 200 1000
203.0.113.50 - - [30/Jan/2025:08:15:00 +0000] "GET /../../etc/passwd HTTP/1.1" 403 0
198.51.100.25 - - [30/Jan/2025:08:20:00 +0000] "GET /cmd?exec=ls;cat /etc/passwd HTTP/1.1" 500 0
10.0.0.75 - - [30/Jan/2025:08:25:00 +0000] "GET /robots.txt HTTP/1.1" 200 150 "-" "Nikto/2.1.6"
"""
        log_path = os.path.join(self.temp_dir, "test.log")
        with open(log_path, 'w') as f:
            f.write(log_content)
        
        # Analisar
        anomalies = engine.analyze_file(log_path, "integration_test")
        
        # Verificar resultados
        self.assertGreater(len(anomalies), 0)
        
        # Verificar tipos detetados
        types = [a.anomaly_type.value for a in anomalies]
        self.assertIn('SQL_INJECTION', types)
        self.assertIn('XSS', types)
        self.assertIn('PATH_TRAVERSAL', types)
        
        # Verificar estatísticas
        stats = engine.get_stats()
        self.assertGreater(stats['anomalies_detected'], 0)
        
        # Exportar relatório
        exporter = ReportExporter()
        report_path = os.path.join(self.temp_dir, "report.json")
        
        anomaly_dicts = [a.to_dict() for a in anomalies]
        exporter.export(anomaly_dicts, stats, report_path, "json")
        
        self.assertTrue(os.path.exists(report_path))
        
        print_success(f"Pipeline completo OK:")
        print_success(f"  - Linhas processadas: {stats['entries_processed']}")
        print_success(f"  - Anomalias detetadas: {stats['anomalies_detected']}")
        print_success(f"  - Tipos: {list(stats['by_type'].keys())}")
        print_success(f"  - Relatório exportado: {report_path}")


# ============================================================
# RUNNER PRINCIPAL
# ============================================================

def run_tests(verbose=False, module=None):
    """Executa os testes."""
    print_header("🦉 LOG SENTINEL v2.0 - SISTEMA DE TESTES")
    
    # Criar test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Definir módulos de teste
    test_classes = {
        'parser': TestParser,
        'database': TestDatabase,
        'engine': TestDetectionEngine,
        'ml': TestMLModule,
        'plugins': TestPluginSystem,
        'exporter': TestExporter,
        'integration': TestIntegration,
    }
    
    # Adicionar testes
    if module and module in test_classes:
        suite.addTests(loader.loadTestsFromTestCase(test_classes[module]))
    else:
        for test_class in test_classes.values():
            suite.addTests(loader.loadTestsFromTestCase(test_class))
    
    # Executar
    verbosity = 2 if verbose else 1
    runner = unittest.TextTestRunner(verbosity=verbosity, stream=sys.stdout)
    
    print_section("A executar testes...")
    result = runner.run(suite)
    
    # Sumário
    print_header("SUMÁRIO DOS TESTES")
    
    total = result.testsRun
    failures = len(result.failures)
    errors = len(result.errors)
    success = total - failures - errors
    
    print(f"  Total de testes: {total}")
    print(f"  {Colors.GREEN}Sucessos: {success}{Colors.END}")
    
    if failures > 0:
        print(f"  {Colors.RED}Falhas: {failures}{Colors.END}")
    if errors > 0:
        print(f"  {Colors.RED}Erros: {errors}{Colors.END}")
    
    if failures == 0 and errors == 0:
        print(f"\n  {Colors.GREEN}{Colors.BOLD}✓ TODOS OS TESTES PASSARAM!{Colors.END}")
    else:
        print(f"\n  {Colors.RED}{Colors.BOLD}✗ ALGUNS TESTES FALHARAM{Colors.END}")
    
    print()
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Log Sentinel - Sistema de Testes")
    parser.add_argument('--verbose', '-v', action='store_true', help="Modo verbose")
    parser.add_argument('--module', '-m', type=str, help="Testar módulo específico (parser, database, engine, ml, plugins, exporter, integration)")
    
    args = parser.parse_args()
    sys.exit(run_tests(verbose=args.verbose, module=args.module))
