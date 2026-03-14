"""
Log Sentinel v2.0 - SIEM Integration
=====================================
Integração com sistemas SIEM (Security Information and Event Management).

Suporta:
- Syslog (RFC 5424)
- Webhook (HTTP POST)
- ELK Stack (Elasticsearch)
- Ficheiro JSON (para importação)

Author: Duarte Cunha (Nº 2024271)
ISTEC - Instituto Superior de Tecnologias Avançadas de Lisboa
Ano Letivo: 2025/2026
"""

import socket
import json
import threading
from datetime import datetime
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
import queue
import time

# HTTP requests (opcional)
try:
    import urllib.request
    import urllib.error
    HTTP_AVAILABLE = True
except ImportError:
    HTTP_AVAILABLE = False


class SIEMType(Enum):
    """Tipos de SIEM suportados."""
    SYSLOG = "syslog"
    WEBHOOK = "webhook"
    ELASTICSEARCH = "elasticsearch"
    FILE = "file"
    SPLUNK = "splunk"


class SyslogSeverity(Enum):
    """Severidades Syslog (RFC 5424)."""
    EMERGENCY = 0
    ALERT = 1
    CRITICAL = 2
    ERROR = 3
    WARNING = 4
    NOTICE = 5
    INFO = 6
    DEBUG = 7


class SyslogFacility(Enum):
    """Facilidades Syslog."""
    LOCAL0 = 16
    LOCAL1 = 17
    LOCAL2 = 18
    LOCAL3 = 19
    LOCAL4 = 20
    LOCAL5 = 21
    LOCAL6 = 22
    LOCAL7 = 23


@dataclass
class SIEMEvent:
    """Evento para envio ao SIEM."""
    timestamp: str
    source: str
    event_type: str
    severity: str
    message: str
    source_ip: Optional[str] = None
    target: Optional[str] = None
    raw_log: Optional[str] = None
    ml_score: Optional[float] = None
    tags: Optional[List[str]] = None
    custom_fields: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict:
        """Converte para dicionário."""
        d = asdict(self)
        d['application'] = 'LogSentinel'
        d['version'] = '2.0'
        return {k: v for k, v in d.items() if v is not None}
    
    def to_json(self) -> str:
        """Converte para JSON."""
        return json.dumps(self.to_dict(), default=str)
    
    def to_syslog(self, facility: SyslogFacility = SyslogFacility.LOCAL0) -> str:
        """Converte para formato Syslog RFC 5424."""
        # Mapear severidade
        severity_map = {
            'CRITICAL': SyslogSeverity.CRITICAL,
            'HIGH': SyslogSeverity.ERROR,
            'MEDIUM': SyslogSeverity.WARNING,
            'LOW': SyslogSeverity.NOTICE
        }
        sev = severity_map.get(self.severity.upper(), SyslogSeverity.INFO)
        
        # Calcular PRI
        pri = facility.value * 8 + sev.value
        
        # Formato RFC 5424
        # <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
        timestamp = datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        hostname = socket.gethostname()
        app_name = "LogSentinel"
        proc_id = "-"
        msg_id = self.event_type.upper().replace(" ", "_")
        
        # Structured data
        sd = f'[logsentinel@0 severity="{self.severity}" type="{self.event_type}"'
        if self.source_ip:
            sd += f' sourceIP="{self.source_ip}"'
        if self.ml_score:
            sd += f' mlScore="{self.ml_score:.2f}"'
        sd += ']'
        
        msg = self.message.replace('\n', ' ')
        
        return f"<{pri}>1 {timestamp} {hostname} {app_name} {proc_id} {msg_id} {sd} {msg}"
    
    def to_cef(self) -> str:
        """Converte para formato CEF (Common Event Format)."""
        # CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
        severity_map = {'CRITICAL': 10, 'HIGH': 7, 'MEDIUM': 5, 'LOW': 3}
        sev = severity_map.get(self.severity.upper(), 5)
        
        extension = f"msg={self.message}"
        if self.source_ip:
            extension += f" src={self.source_ip}"
        if self.target:
            extension += f" dst={self.target}"
        
        return f"CEF:0|LogSentinel|SecurityAnalyzer|2.0|{self.event_type}|{self.event_type}|{sev}|{extension}"


class SIEMConnector:
    """Conector base para SIEM."""
    
    def __init__(self, config: Dict):
        self.config = config
        self.enabled = config.get('enabled', True)
        self.name = config.get('name', 'Unknown')
    
    def send(self, event: SIEMEvent) -> bool:
        """Envia evento. Deve ser implementado pelas subclasses."""
        raise NotImplementedError
    
    def test_connection(self) -> bool:
        """Testa conexão. Deve ser implementado pelas subclasses."""
        raise NotImplementedError
    
    def close(self):
        """Fecha conexão."""
        pass


class SyslogConnector(SIEMConnector):
    """Conector para Syslog."""
    
    def __init__(self, config: Dict):
        super().__init__(config)
        self.host = config.get('host', 'localhost')
        self.port = config.get('port', 514)
        self.protocol = config.get('protocol', 'udp').lower()
        self.facility = SyslogFacility[config.get('facility', 'LOCAL0').upper()]
        self._socket: Optional[socket.socket] = None
    
    def _get_socket(self) -> socket.socket:
        """Obtém ou cria socket."""
        if self._socket is None:
            if self.protocol == 'tcp':
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._socket.connect((self.host, self.port))
            else:
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return self._socket
    
    def send(self, event: SIEMEvent) -> bool:
        """Envia evento via Syslog."""
        if not self.enabled:
            return False
        
        try:
            message = event.to_syslog(self.facility)
            sock = self._get_socket()
            
            if self.protocol == 'tcp':
                sock.sendall((message + '\n').encode('utf-8'))
            else:
                sock.sendto(message.encode('utf-8'), (self.host, self.port))
            
            return True
        except Exception as e:
            print(f"[SIEM] Erro Syslog: {e}")
            self._socket = None
            return False
    
    def test_connection(self) -> bool:
        """Testa conexão Syslog."""
        try:
            test_event = SIEMEvent(
                timestamp=datetime.now().isoformat(),
                source="LogSentinel",
                event_type="TEST",
                severity="INFO",
                message="Connection test"
            )
            return self.send(test_event)
        except:
            return False
    
    def close(self):
        """Fecha socket."""
        if self._socket:
            self._socket.close()
            self._socket = None


class WebhookConnector(SIEMConnector):
    """Conector para Webhook HTTP."""
    
    def __init__(self, config: Dict):
        super().__init__(config)
        self.url = config.get('url', '')
        self.method = config.get('method', 'POST')
        self.headers = config.get('headers', {'Content-Type': 'application/json'})
        self.timeout = config.get('timeout', 10)
        self.auth_token = config.get('auth_token')
        
        if self.auth_token:
            self.headers['Authorization'] = f'Bearer {self.auth_token}'
    
    def send(self, event: SIEMEvent) -> bool:
        """Envia evento via HTTP."""
        if not self.enabled or not HTTP_AVAILABLE:
            return False
        
        try:
            data = event.to_json().encode('utf-8')
            req = urllib.request.Request(
                self.url,
                data=data,
                headers=self.headers,
                method=self.method
            )
            
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                return response.status == 200 or response.status == 201
                
        except Exception as e:
            print(f"[SIEM] Erro Webhook: {e}")
            return False
    
    def test_connection(self) -> bool:
        """Testa conexão HTTP."""
        try:
            req = urllib.request.Request(self.url, method='HEAD')
            with urllib.request.urlopen(req, timeout=5) as response:
                return response.status < 400
        except:
            return False


class ElasticsearchConnector(SIEMConnector):
    """Conector para Elasticsearch / ELK Stack."""
    
    def __init__(self, config: Dict):
        super().__init__(config)
        self.host = config.get('host', 'localhost')
        self.port = config.get('port', 9200)
        self.index = config.get('index', 'logsentinel')
        self.use_ssl = config.get('use_ssl', False)
        self.username = config.get('username')
        self.password = config.get('password')
        
        protocol = 'https' if self.use_ssl else 'http'
        self.base_url = f"{protocol}://{self.host}:{self.port}"
    
    def send(self, event: SIEMEvent) -> bool:
        """Envia evento para Elasticsearch."""
        if not self.enabled or not HTTP_AVAILABLE:
            return False
        
        try:
            # Index com data
            index_name = f"{self.index}-{datetime.now().strftime('%Y.%m.%d')}"
            url = f"{self.base_url}/{index_name}/_doc"
            
            headers = {'Content-Type': 'application/json'}
            
            # Autenticação básica
            if self.username and self.password:
                import base64
                credentials = base64.b64encode(
                    f"{self.username}:{self.password}".encode()
                ).decode()
                headers['Authorization'] = f'Basic {credentials}'
            
            data = event.to_json().encode('utf-8')
            req = urllib.request.Request(url, data=data, headers=headers, method='POST')
            
            with urllib.request.urlopen(req, timeout=10) as response:
                return response.status == 201
                
        except Exception as e:
            print(f"[SIEM] Erro Elasticsearch: {e}")
            return False
    
    def test_connection(self) -> bool:
        """Testa conexão com Elasticsearch."""
        try:
            req = urllib.request.Request(self.base_url)
            with urllib.request.urlopen(req, timeout=5) as response:
                return response.status == 200
        except:
            return False


class FileConnector(SIEMConnector):
    """Conector para ficheiro local (JSON Lines)."""
    
    def __init__(self, config: Dict):
        super().__init__(config)
        self.filepath = Path(config.get('filepath', 'siem_events.jsonl'))
        self.max_size_mb = config.get('max_size_mb', 100)
        self.rotate = config.get('rotate', True)
        self._lock = threading.Lock()
    
    def send(self, event: SIEMEvent) -> bool:
        """Escreve evento para ficheiro."""
        if not self.enabled:
            return False
        
        try:
            with self._lock:
                # Verificar rotação
                if self.rotate and self.filepath.exists():
                    size_mb = self.filepath.stat().st_size / (1024 * 1024)
                    if size_mb > self.max_size_mb:
                        self._rotate_file()
                
                # Escrever evento
                with open(self.filepath, 'a', encoding='utf-8') as f:
                    f.write(event.to_json() + '\n')
                
                return True
        except Exception as e:
            print(f"[SIEM] Erro File: {e}")
            return False
    
    def _rotate_file(self):
        """Rotaciona ficheiro."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        new_path = self.filepath.with_suffix(f'.{timestamp}.jsonl')
        self.filepath.rename(new_path)
    
    def test_connection(self) -> bool:
        """Testa escrita no ficheiro."""
        try:
            self.filepath.parent.mkdir(parents=True, exist_ok=True)
            return True
        except:
            return False


class SIEMIntegration:
    """Gestor de integração SIEM."""
    
    CONNECTOR_TYPES = {
        SIEMType.SYSLOG: SyslogConnector,
        SIEMType.WEBHOOK: WebhookConnector,
        SIEMType.ELASTICSEARCH: ElasticsearchConnector,
        SIEMType.FILE: FileConnector,
    }
    
    def __init__(self, config_path: str = None):
        self.connectors: List[SIEMConnector] = []
        self.event_queue: queue.Queue = queue.Queue()
        self._running = False
        self._worker_thread: Optional[threading.Thread] = None
        
        # Estatísticas
        self.stats = {
            'events_sent': 0,
            'events_failed': 0,
            'last_event': None
        }
        
        # Carregar configuração
        if config_path and Path(config_path).exists():
            self.load_config(config_path)
    
    def load_config(self, config_path: str):
        """Carrega configuração de ficheiro."""
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            
            for conn_config in config.get('connectors', []):
                self.add_connector(conn_config)
                
        except Exception as e:
            print(f"[SIEM] Erro ao carregar config: {e}")
    
    def add_connector(self, config: Dict) -> bool:
        """Adiciona conector."""
        try:
            siem_type = SIEMType(config.get('type', 'file'))
            connector_class = self.CONNECTOR_TYPES.get(siem_type)
            
            if connector_class:
                connector = connector_class(config)
                self.connectors.append(connector)
                print(f"[SIEM] Conector adicionado: {config.get('name', siem_type.value)}")
                return True
        except Exception as e:
            print(f"[SIEM] Erro ao adicionar conector: {e}")
        return False
    
    def remove_connector(self, name: str):
        """Remove conector por nome."""
        self.connectors = [c for c in self.connectors if c.name != name]
    
    def send_event(self, event: SIEMEvent, async_send: bool = True):
        """Envia evento para todos os conectores."""
        if async_send and self._running:
            self.event_queue.put(event)
        else:
            self._send_to_all(event)
    
    def send_anomaly(self, anomaly: 'Anomaly'):
        """Converte e envia anomalia."""
        event = SIEMEvent(
            timestamp=anomaly.timestamp.isoformat() if anomaly.timestamp else datetime.now().isoformat(),
            source=anomaly.log_file or "unknown",
            event_type=anomaly.anomaly_type.value if hasattr(anomaly.anomaly_type, 'value') else str(anomaly.anomaly_type),
            severity=anomaly.severity.value if hasattr(anomaly.severity, 'value') else str(anomaly.severity),
            message=anomaly.detail,
            source_ip=anomaly.source_ip,
            target=anomaly.target,
            raw_log=anomaly.evidence[0] if anomaly.evidence else None,
            ml_score=anomaly.ml_score,
            tags=[anomaly.anomaly_type.value] if hasattr(anomaly.anomaly_type, 'value') else None
        )
        self.send_event(event)
    
    def _send_to_all(self, event: SIEMEvent):
        """Envia para todos os conectores."""
        for connector in self.connectors:
            try:
                if connector.send(event):
                    self.stats['events_sent'] += 1
                else:
                    self.stats['events_failed'] += 1
            except Exception as e:
                print(f"[SIEM] Erro ao enviar: {e}")
                self.stats['events_failed'] += 1
        
        self.stats['last_event'] = datetime.now()
    
    def _worker(self):
        """Worker thread para envio assíncrono."""
        while self._running:
            try:
                event = self.event_queue.get(timeout=1)
                self._send_to_all(event)
            except queue.Empty:
                continue
            except Exception as e:
                print(f"[SIEM] Erro no worker: {e}")
    
    def start(self):
        """Inicia processamento assíncrono."""
        if not self._running:
            self._running = True
            self._worker_thread = threading.Thread(target=self._worker, daemon=True)
            self._worker_thread.start()
            print("[SIEM] Integração iniciada")
    
    def stop(self):
        """Para processamento."""
        self._running = False
        if self._worker_thread:
            self._worker_thread.join(timeout=5)
        
        # Fechar conectores
        for connector in self.connectors:
            connector.close()
        
        print("[SIEM] Integração parada")
    
    def test_all(self) -> Dict[str, bool]:
        """Testa todos os conectores."""
        results = {}
        for connector in self.connectors:
            results[connector.name] = connector.test_connection()
        return results
    
    def get_stats(self) -> Dict:
        """Retorna estatísticas."""
        return {
            **self.stats,
            'connectors': len(self.connectors),
            'queue_size': self.event_queue.qsize(),
            'running': self._running
        }


# Configuração padrão
DEFAULT_CONFIG = {
    "connectors": [
        {
            "name": "Local File",
            "type": "file",
            "enabled": True,
            "filepath": "data/siem_events.jsonl",
            "max_size_mb": 50,
            "rotate": True
        }
    ]
}


def create_default_config(filepath: str = "siem_config.json"):
    """Cria ficheiro de configuração padrão."""
    with open(filepath, 'w') as f:
        json.dump(DEFAULT_CONFIG, f, indent=2)
    print(f"[SIEM] Configuração criada: {filepath}")


# Teste
if __name__ == "__main__":
    print("🔌 Teste da Integração SIEM")
    
    # Criar integração com ficheiro local
    siem = SIEMIntegration()
    siem.add_connector({
        "name": "Test File",
        "type": "file",
        "enabled": True,
        "filepath": "test_siem.jsonl"
    })
    
    # Enviar evento de teste
    event = SIEMEvent(
        timestamp=datetime.now().isoformat(),
        source="test.log",
        event_type="SQL_INJECTION",
        severity="CRITICAL",
        message="SQL Injection detected: ' OR '1'='1",
        source_ip="10.0.0.100",
        target="/login"
    )
    
    siem.send_event(event, async_send=False)
    print(f"Stats: {siem.get_stats()}")
    print("✅ Teste concluído!")
