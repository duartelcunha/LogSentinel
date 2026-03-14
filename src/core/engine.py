"""
Log Sentinel v2.0 - Detection Engine
=====================================
Motor de deteção de anomalias com ML integrado.

Author: Duarte Cunha (Nº 2024271)
ISTEC - Instituto Superior de Tecnologias Avançadas de Lisboa
Ano Letivo: 2025/2026
"""

import re
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple, Callable
from dataclasses import dataclass, field
from collections import defaultdict
from enum import Enum
import threading

from .parser import LogEntry, LogParser
from .database import DatabaseManager

# Import ML (opcional)
try:
    # Tentar import relativo primeiro
    from ..ml.anomaly_detector import AnomalyDetector, MLPrediction
    ML_AVAILABLE = True
    print("[ML] Módulo ML importado com sucesso (relativo)")
except ImportError:
    try:
        # Tentar import absoluto
        from src.ml.anomaly_detector import AnomalyDetector, MLPrediction
        ML_AVAILABLE = True
        print("[ML] Módulo ML importado com sucesso (absoluto)")
    except ImportError:
        try:
            # Tentar import direto
            import sys
            from pathlib import Path
            ml_path = Path(__file__).parent.parent / 'ml'
            sys.path.insert(0, str(ml_path.parent))
            from ml.anomaly_detector import AnomalyDetector, MLPrediction
            ML_AVAILABLE = True
            print("[ML] Módulo ML importado com sucesso (direto)")
        except ImportError as e:
            ML_AVAILABLE = False
            print(f"[ML] ERRO ao importar ML: {e}")


class Severity(Enum):
    """Níveis de severidade."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AnomalyType(Enum):
    """Tipos de anomalias."""
    BRUTE_FORCE = "BRUTE_FORCE"
    SQL_INJECTION = "SQL_INJECTION"
    XSS = "XSS"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    COMMAND_INJECTION = "COMMAND_INJECTION"
    DDOS = "DDOS"
    PORT_SCAN = "PORT_SCAN"
    SCANNER = "SCANNER"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    SUSPICIOUS_ACCESS = "SUSPICIOUS_ACCESS"
    UNAUTHORIZED_ACCESS = "UNAUTHORIZED_ACCESS"
    LFI_RFI = "LFI_RFI"
    XXE = "XXE"
    ML_DETECTED = "ML_DETECTED"


@dataclass
class Anomaly:
    """Estrutura de anomalia detetada."""
    anomaly_type: AnomalyType
    severity: Severity
    detail: str
    source_ip: Optional[str] = None
    target: Optional[str] = None
    evidence: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)
    score: float = 0.0
    ml_score: float = None
    count: int = 1
    log_file: Optional[str] = None
    correlation_id: Optional[str] = None
    
    def to_dict(self) -> Dict:
        """Converte para dicionário."""
        return {
            'type': self.anomaly_type.value,
            'severity': self.severity.value,
            'detail': self.detail,
            'source_ip': self.source_ip,
            'target': self.target,
            'evidence': self.evidence,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'score': self.score,
            'ml_score': self.ml_score,
            'count': self.count,
            'log_file': self.log_file,
        }


class DetectionEngine:
    """
    Motor de deteção de anomalias.
    
    Combina:
    - Análise de padrões (regex)
    - Análise temporal
    - Machine Learning
    - Correlação de eventos
    """
    
    # Thresholds
    THRESHOLDS = {
        'brute_force_attempts': 5,
        'brute_force_window': 300,
        'ddos_requests': 100,
        'ddos_window': 60,
        'scanner_requests': 20,
    }
    
    # Severidade por tipo
    SEVERITY_MAP = {
        AnomalyType.BRUTE_FORCE: Severity.HIGH,
        AnomalyType.SQL_INJECTION: Severity.CRITICAL,
        AnomalyType.XSS: Severity.HIGH,
        AnomalyType.PATH_TRAVERSAL: Severity.HIGH,
        AnomalyType.COMMAND_INJECTION: Severity.CRITICAL,
        AnomalyType.DDOS: Severity.CRITICAL,
        AnomalyType.PORT_SCAN: Severity.MEDIUM,
        AnomalyType.SCANNER: Severity.MEDIUM,
        AnomalyType.PRIVILEGE_ESCALATION: Severity.CRITICAL,
        AnomalyType.SUSPICIOUS_ACCESS: Severity.LOW,
        AnomalyType.UNAUTHORIZED_ACCESS: Severity.HIGH,
        AnomalyType.LFI_RFI: Severity.CRITICAL,
        AnomalyType.XXE: Severity.CRITICAL,
        AnomalyType.ML_DETECTED: Severity.MEDIUM,
    }
    
    # Padrões de ataque
    ATTACK_PATTERNS = {
        AnomalyType.SQL_INJECTION: [
            re.compile(r"(?i)(\bunion\b.*\bselect\b|\bselect\b.*\bfrom\b.*\bwhere\b)"),
            re.compile(r"(?i)('|\")\s*(or|and)\s+[\d\w]+\s*[=<>]"),
            re.compile(r"(?i)\b(drop|delete|insert|update|alter)\s+(table|database|into)\b"),
            re.compile(r"(?i)1\s*=\s*1|'='|or\s+1\s*=\s*1"),
        ],
        AnomalyType.XSS: [
            re.compile(r"(?i)<script[^>]*>"),
            re.compile(r"(?i)javascript\s*:"),
            re.compile(r"(?i)on(load|error|click|mouse)\s*="),
            re.compile(r"(?i)<iframe[^>]*>"),
        ],
        AnomalyType.PATH_TRAVERSAL: [
            re.compile(r"\.\.(/|\\|%2f|%5c)", re.IGNORECASE),
            re.compile(r"(?i)/etc/(passwd|shadow|hosts)"),
            re.compile(r"(?i)/proc/(self|version)"),
        ],
        AnomalyType.COMMAND_INJECTION: [
            re.compile(r"[;&|`]"),
            re.compile(r"\$\([^)]+\)"),
            re.compile(r"(?i)\b(wget|curl|nc|bash|sh|cmd|powershell)\b"),
        ],
        AnomalyType.SCANNER: [
            re.compile(r"(?i)(nikto|nmap|sqlmap|dirbuster|gobuster|wpscan)"),
            re.compile(r"(?i)/(\.git|\.svn|\.env|\.htaccess)"),
            re.compile(r"(?i)/wp-(admin|login|includes)"),
            re.compile(r"(?i)/(phpmyadmin|phpinfo|adminer)"),
        ],
        AnomalyType.LFI_RFI: [
            re.compile(r"(?i)(file|php|data|expect)://"),
            re.compile(r"(?i)\?.*=.*(\.php|\.txt|\.log)"),
        ],
        AnomalyType.XXE: [
            re.compile(r"(?i)<!DOCTYPE[^>]*\["),
            re.compile(r"(?i)<!ENTITY"),
        ],
    }
    
    def __init__(self, db: DatabaseManager = None, enable_ml: bool = True):
        """Inicializa o motor."""
        self.db = db
        self.parser = LogParser()
        
        # Estado temporal
        self._failed_logins: Dict[str, List[datetime]] = defaultdict(list)
        self._request_counts: Dict[str, List[datetime]] = defaultdict(list)
        self._scanner_hits: Dict[str, int] = defaultdict(int)
        
        # ML
        self.ml_detector = None
        if enable_ml and ML_AVAILABLE:
            try:
                self.ml_detector = AnomalyDetector()
            except Exception as e:
                print(f"ML não disponível: {e}")
        
        # Anomalias e stats
        self.anomalies: List[Anomaly] = []
        self.stats = {
            'entries_processed': 0,
            'anomalies_detected': 0,
            'by_type': defaultdict(int),
            'by_severity': defaultdict(int),
            'ml_detections': 0,
        }
        
        # Callbacks
        self._on_anomaly_callbacks: List[Callable] = []
    
    def on_anomaly(self, callback: Callable[[Anomaly], None]) -> None:
        """Regista callback para novas anomalias."""
        self._on_anomaly_callbacks.append(callback)
    
    def _notify_anomaly(self, anomaly: Anomaly) -> None:
        """Notifica callbacks de nova anomalia."""
        for callback in self._on_anomaly_callbacks:
            try:
                callback(anomaly)
            except Exception as e:
                print(f"Erro em callback: {e}")
    
    def analyze_file(self, filepath: str, session_id: str = None,
                     progress_callback: Callable = None) -> List[Anomaly]:
        """Analisa um ficheiro de log."""
        anomalies = []
        
        def on_progress(current, total):
            if progress_callback:
                progress_callback(current, total)
        
        for entry in self.parser.parse_file(filepath, callback=on_progress):
            self.stats['entries_processed'] += 1
            
            # Análise de padrões
            entry_anomalies = self._analyze_entry(entry, filepath)
            
            # Análise ML
            if self.ml_detector and self.ml_detector.is_trained:
                ml_result = self.ml_detector.predict(entry.to_dict())
                if ml_result.is_anomaly and ml_result.confidence > 0.7:
                    # Apenas adicionar se não foi detetado por padrões
                    if not entry_anomalies:
                        ml_anomaly = Anomaly(
                            anomaly_type=AnomalyType.ML_DETECTED,
                            severity=Severity.MEDIUM,
                            source_ip=entry.source_ip,
                            target=entry.target,
                            detail=f"Anomalia detetada por ML (confiança: {ml_result.confidence:.1%})",
                            evidence=[entry.raw_line],
                            timestamp=entry.timestamp or datetime.now(),
                            score=ml_result.confidence,
                            ml_score=ml_result.anomaly_score,
                        )
                        entry_anomalies.append(ml_anomaly)
                        self.stats['ml_detections'] += 1
            
            for anomaly in entry_anomalies:
                anomaly.log_file = filepath
                anomalies.append(anomaly)
                self._record_anomaly(anomaly, session_id)
                self._notify_anomaly(anomaly)
        
        # Análise temporal final
        temporal_anomalies = self._analyze_temporal()
        for anomaly in temporal_anomalies:
            anomaly.log_file = filepath
            anomalies.append(anomaly)
            self._record_anomaly(anomaly, session_id)
        
        # Treinar modelo ML automaticamente com os dados
        print(f"[DEBUG] entries_processed={self.stats['entries_processed']}, ml_detector={self.ml_detector is not None}")
        if self.ml_detector and self.stats['entries_processed'] >= 20:
            try:
                # Recolher dados para treino
                training_data = []
                for entry in self.parser.parse_file(filepath):
                    entry_dict = entry.to_dict()
                    training_data.append(entry_dict)
                
                print(f"[ML] Dados recolhidos: {len(training_data)} entradas")
                
                if len(training_data) >= 20:
                    # Treinar o modelo
                    print("[ML] A treinar modelo...")
                    result = self.ml_detector.train_anomaly_detector(training_data, contamination=0.15)
                    print(f"[ML] Resultado treino: {result}")
                    
                    # Verificar se treinou com sucesso
                    if self.ml_detector.is_trained:
                        self.stats['ml_trained'] = True
                        print("[ML] Modelo treinado com sucesso!")
                        
                        # Fazer predições com o modelo treinado
                        ml_count = 0
                        for entry_dict in training_data:
                            ml_result = self.ml_detector.predict(entry_dict)
                            if ml_result.is_anomaly and ml_result.confidence > 0.7:
                                source_ip = entry_dict.get('source_ip')
                                already_detected = any(
                                    a.source_ip == source_ip for a in anomalies
                                    if a.anomaly_type != AnomalyType.ML_DETECTED
                                )
                                if not already_detected and ml_count < 10:
                                    ml_anomaly = Anomaly(
                                        anomaly_type=AnomalyType.ML_DETECTED,
                                        severity=Severity.MEDIUM,
                                        source_ip=source_ip,
                                        target=entry_dict.get('url') or entry_dict.get('target'),
                                        detail=f"Comportamento anómalo detetado por IA (confiança: {ml_result.confidence:.0%})",
                                        evidence=[str(entry_dict.get('raw_line', ''))[:200]],
                                        timestamp=entry_dict.get('timestamp') if isinstance(entry_dict.get('timestamp'), datetime) else datetime.now(),
                                        score=ml_result.confidence,
                                        ml_score=ml_result.anomaly_score,
                                        log_file=filepath
                                    )
                                    anomalies.append(ml_anomaly)
                                    self._record_anomaly(ml_anomaly, session_id)
                                    self.stats['ml_detections'] += 1
                                    ml_count += 1
                    else:
                        print(f"[ML] Treino falhou: {result.get('error', 'desconhecido')}")
            except Exception as e:
                print(f"[ML] Erro: {e}")
                import traceback
                traceback.print_exc()
        
        self.anomalies = anomalies
        return anomalies
    
    def analyze_entry(self, entry: LogEntry) -> List[Anomaly]:
        """Analisa uma entrada individual."""
        return self._analyze_entry(entry, None)
    
    def _analyze_entry(self, entry: LogEntry, filepath: str) -> List[Anomaly]:
        """Análise interna de uma entrada."""
        anomalies = []
        
        # Verificar padrões de ataque
        text_to_analyze = entry.raw_line
        if entry.extra.get('url'):
            text_to_analyze += " " + entry.extra['url']
        
        for attack_type, patterns in self.ATTACK_PATTERNS.items():
            for pattern in patterns:
                if pattern.search(text_to_analyze):
                    severity = self.SEVERITY_MAP.get(attack_type, Severity.MEDIUM)
                    anomaly = Anomaly(
                        anomaly_type=attack_type,
                        severity=severity,
                        source_ip=entry.source_ip,
                        target=entry.target or entry.extra.get('url'),
                        detail=f"Padrão de {attack_type.value} detetado",
                        evidence=[entry.raw_line],
                        timestamp=entry.timestamp or datetime.now(),
                        score=self._calculate_score(attack_type, 1),
                    )
                    anomalies.append(anomaly)
                    break
        
        # Análise específica por tipo de log
        if entry.log_type == "AUTH":
            anomalies.extend(self._analyze_auth(entry))
        elif entry.log_type in ["WEB_ACCESS", "WEB_ERROR"]:
            anomalies.extend(self._analyze_web_access(entry))
        
        return anomalies
    
    def _analyze_auth(self, entry: LogEntry) -> List[Anomaly]:
        """Analisa logs de autenticação."""
        anomalies = []
        
        if entry.status == 'FAILED' and entry.source_ip:
            ip = entry.source_ip
            now = entry.timestamp or datetime.now()
            
            self._failed_logins[ip].append(now)
            
            # Limpar antigos
            window = timedelta(seconds=self.THRESHOLDS['brute_force_window'])
            self._failed_logins[ip] = [t for t in self._failed_logins[ip] if now - t <= window]
            
            count = len(self._failed_logins[ip])
            if count >= self.THRESHOLDS['brute_force_attempts']:
                anomaly = Anomaly(
                    anomaly_type=AnomalyType.BRUTE_FORCE,
                    severity=Severity.HIGH,
                    source_ip=ip,
                    target=entry.user,
                    detail=f"Brute-force: {count} tentativas em {self.THRESHOLDS['brute_force_window']}s",
                    evidence=[entry.raw_line],
                    timestamp=now,
                    score=self._calculate_score(AnomalyType.BRUTE_FORCE, count),
                    count=count,
                )
                anomalies.append(anomaly)
                self._failed_logins[ip] = []
        
        return anomalies
    
    def _analyze_web_access(self, entry: LogEntry) -> List[Anomaly]:
        """Analisa logs de acesso web."""
        anomalies = []
        
        ip = entry.source_ip
        url = entry.extra.get('url', '')
        status = entry.status
        now = entry.timestamp or datetime.now()
        
        # DDoS detection
        if ip:
            self._request_counts[ip].append(now)
            window = timedelta(seconds=self.THRESHOLDS['ddos_window'])
            self._request_counts[ip] = [t for t in self._request_counts[ip] if now - t <= window]
            
            count = len(self._request_counts[ip])
            if count >= self.THRESHOLDS['ddos_requests']:
                anomaly = Anomaly(
                    anomaly_type=AnomalyType.DDOS,
                    severity=Severity.CRITICAL,
                    source_ip=ip,
                    detail=f"Possível DDoS: {count} requests em {self.THRESHOLDS['ddos_window']}s",
                    timestamp=now,
                    score=min(1.0, count / 200),
                    count=count,
                )
                anomalies.append(anomaly)
                self._request_counts[ip] = []
        
        # Unauthorized access
        if status in ['401', '403']:
            anomaly = Anomaly(
                anomaly_type=AnomalyType.UNAUTHORIZED_ACCESS,
                severity=Severity.LOW,
                source_ip=ip,
                target=url,
                detail=f"Acesso não autorizado (HTTP {status})",
                evidence=[entry.raw_line],
                timestamp=now,
                score=0.3,
            )
            anomalies.append(anomaly)
        
        return anomalies
    
    def _analyze_temporal(self) -> List[Anomaly]:
        """Análise temporal final."""
        anomalies = []
        
        for ip, attempts in self._failed_logins.items():
            if len(attempts) >= 3:
                anomaly = Anomaly(
                    anomaly_type=AnomalyType.SUSPICIOUS_ACCESS,
                    severity=Severity.LOW,
                    source_ip=ip,
                    detail=f"IP suspeito: {len(attempts)} tentativas falhadas",
                    timestamp=datetime.now(),
                    score=0.4,
                    count=len(attempts),
                )
                anomalies.append(anomaly)
        
        return anomalies
    
    def _calculate_score(self, attack_type: AnomalyType, count: int) -> float:
        """Calcula score de risco."""
        base_scores = {
            AnomalyType.SQL_INJECTION: 0.9,
            AnomalyType.COMMAND_INJECTION: 0.95,
            AnomalyType.XSS: 0.7,
            AnomalyType.PATH_TRAVERSAL: 0.8,
            AnomalyType.BRUTE_FORCE: 0.75,
            AnomalyType.DDOS: 0.85,
            AnomalyType.SCANNER: 0.5,
            AnomalyType.LFI_RFI: 0.85,
            AnomalyType.XXE: 0.9,
        }
        base = base_scores.get(attack_type, 0.5)
        return min(1.0, base + min(0.1, count * 0.01))
    
    def _record_anomaly(self, anomaly: Anomaly, session_id: str = None) -> None:
        """Regista anomalia."""
        self.stats['anomalies_detected'] += 1
        self.stats['by_type'][anomaly.anomaly_type.value] += 1
        self.stats['by_severity'][anomaly.severity.value] += 1
        
        if self.db:
            anomaly_id = self.db.insert_anomaly(
                anomaly_type=anomaly.anomaly_type.value,
                detail=anomaly.detail,
                severity=anomaly.severity.value,
                source_ip=anomaly.source_ip,
                target=anomaly.target,
                log_line=anomaly.evidence[0] if anomaly.evidence else None,
                log_file=anomaly.log_file,
                session_id=session_id,
                score=anomaly.score,
                ml_score=anomaly.ml_score,
            )
            
            # Criar alerta para severidades altas
            if anomaly.severity in [Severity.HIGH, Severity.CRITICAL]:
                self.db.create_alert(
                    anomaly_id=anomaly_id,
                    alert_type=anomaly.anomaly_type.value,
                    severity=anomaly.severity.value,
                    title=f"{anomaly.anomaly_type.value} Detetado",
                    message=anomaly.detail
                )
    
    def correlate_anomalies(self) -> List[Dict]:
        """Correlaciona anomalias relacionadas."""
        correlations = []
        
        # Agrupar por IP
        by_ip = defaultdict(list)
        for i, a in enumerate(self.anomalies):
            if a.source_ip:
                by_ip[a.source_ip].append((i, a))
        
        # Encontrar IPs com múltiplos tipos de ataque
        for ip, anomaly_list in by_ip.items():
            if len(anomaly_list) >= 3:
                types = set(a.anomaly_type.value for _, a in anomaly_list)
                if len(types) >= 2:
                    correlation = {
                        'type': 'multi_vector_attack',
                        'ip': ip,
                        'attack_types': list(types),
                        'count': len(anomaly_list),
                        'confidence': min(0.9, len(types) * 0.3),
                        'description': f"Ataque multi-vetor de {ip}: {', '.join(types)}"
                    }
                    correlations.append(correlation)
                    
                    # Guardar na DB
                    if self.db:
                        anomaly_ids = [i for i, _ in anomaly_list]
                        self.db.add_correlation(
                            anomaly_ids=anomaly_ids,
                            correlation_type='multi_vector_attack',
                            confidence=correlation['confidence'],
                            description=correlation['description']
                        )
        
        return correlations
    
    def get_stats(self) -> Dict:
        """Retorna estatísticas."""
        ml_trained = False
        if self.ml_detector:
            ml_trained = self.ml_detector.is_trained or self.stats.get('ml_trained', False)
        
        return {
            'entries_processed': self.stats['entries_processed'],
            'anomalies_detected': self.stats['anomalies_detected'],
            'by_type': dict(self.stats['by_type']),
            'by_severity': dict(self.stats['by_severity']),
            'ml_detections': self.stats['ml_detections'],
            'parser_stats': self.parser.get_stats(),
            'ml_available': self.ml_detector is not None,
            'ml_trained': ml_trained,
        }
    
    def reset(self) -> None:
        """Reset do motor."""
        self._failed_logins.clear()
        self._request_counts.clear()
        self._scanner_hits.clear()
        self.anomalies.clear()
        self.stats = {
            'entries_processed': 0,
            'anomalies_detected': 0,
            'by_type': defaultdict(int),
            'by_severity': defaultdict(int),
            'ml_detections': 0,
        }
        self.parser.reset_stats()


# Teste
if __name__ == "__main__":
    print("🔧 Teste do DetectionEngine v2")
    engine = DetectionEngine()
    print(f"Stats: {engine.get_stats()}")
    print("✅ Teste concluído!")
