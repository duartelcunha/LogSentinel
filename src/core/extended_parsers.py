"""
Log Sentinel v2.0 - Extended Log Parsers
=========================================
Parsers adicionais para mais formatos de log.

Formatos suportados:
- Windows Event Log (EVTX texto)
- IIS (Internet Information Services)
- PostgreSQL
- MySQL
- Firewall (iptables, pf, Windows Firewall)
- HAProxy
- AWS CloudWatch
- Docker/Container logs

Author: Duarte Cunha (Nº 2024271)
ISTEC - Instituto Superior de Tecnologias Avançadas de Lisboa
Ano Letivo: 2025/2026
"""

import re
import json
from datetime import datetime
from typing import Dict, Optional, List, Tuple
from dataclasses import dataclass, field


@dataclass
class ExtendedLogEntry:
    """Entrada de log estendida."""
    raw_line: str
    timestamp: Optional[datetime] = None
    source_ip: Optional[str] = None
    user: Optional[str] = None
    action: Optional[str] = None
    status: Optional[str] = None
    message: str = ""
    log_type: str = "UNKNOWN"
    line_number: int = 0
    target: Optional[str] = None
    severity: str = "INFO"
    extra: Dict = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            'raw_line': self.raw_line,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'source_ip': self.source_ip,
            'user': self.user,
            'action': self.action,
            'status': self.status,
            'message': self.message,
            'log_type': self.log_type,
            'line_number': self.line_number,
            'target': self.target,
            'severity': self.severity,
            'extra': self.extra
        }


class WindowsEventParser:
    """Parser para Windows Event Logs (formato texto/CSV)."""
    
    # Padrão para logs exportados do Event Viewer
    EVTX_PATTERN = re.compile(
        r'^(?P<date>\d{1,2}/\d{1,2}/\d{4})\s+'
        r'(?P<time>\d{1,2}:\d{2}:\d{2}\s*(?:AM|PM)?)\s+'
        r'(?P<level>\w+)\s+'
        r'(?P<source>\S+)\s+'
        r'(?P<event_id>\d+)\s+'
        r'(?P<category>\S+)?\s*'
        r'(?P<message>.*)$',
        re.IGNORECASE
    )
    
    # Padrão alternativo (PowerShell Get-EventLog)
    POWERSHELL_PATTERN = re.compile(
        r'^(?P<index>\d+)\s+'
        r'(?P<time>\S+\s+\S+\s+\S+)\s+'
        r'(?P<entry_type>\S+)\s+'
        r'(?P<source>\S+)\s+'
        r'(?P<instance_id>\d+)\s+'
        r'(?P<message>.*)$'
    )
    
    # Event IDs importantes para segurança
    SECURITY_EVENTS = {
        4624: ('Logon Success', 'INFO'),
        4625: ('Logon Failure', 'WARNING'),
        4634: ('Logoff', 'INFO'),
        4648: ('Explicit Credential Logon', 'WARNING'),
        4672: ('Special Privileges Assigned', 'INFO'),
        4720: ('User Account Created', 'WARNING'),
        4722: ('User Account Enabled', 'INFO'),
        4724: ('Password Reset Attempt', 'WARNING'),
        4725: ('User Account Disabled', 'INFO'),
        4726: ('User Account Deleted', 'WARNING'),
        4732: ('Member Added to Security Group', 'WARNING'),
        4756: ('Member Added to Universal Security Group', 'WARNING'),
        4768: ('Kerberos TGT Requested', 'INFO'),
        4769: ('Kerberos Service Ticket Requested', 'INFO'),
        4771: ('Kerberos Pre-Auth Failed', 'WARNING'),
        4776: ('Credential Validation', 'INFO'),
        1102: ('Audit Log Cleared', 'CRITICAL'),
        7045: ('Service Installed', 'WARNING'),
    }
    
    def parse(self, line: str, line_number: int = 0) -> Optional[ExtendedLogEntry]:
        """Parse linha de Windows Event Log."""
        # Tentar padrão EVTX
        match = self.EVTX_PATTERN.match(line)
        if match:
            d = match.groupdict()
            try:
                # Parse timestamp
                date_str = f"{d['date']} {d['time']}"
                for fmt in ['%m/%d/%Y %I:%M:%S %p', '%m/%d/%Y %H:%M:%S', '%d/%m/%Y %H:%M:%S']:
                    try:
                        timestamp = datetime.strptime(date_str, fmt)
                        break
                    except:
                        timestamp = None
                
                event_id = int(d.get('event_id', 0))
                event_info = self.SECURITY_EVENTS.get(event_id, (d.get('message', ''), 'INFO'))
                
                return ExtendedLogEntry(
                    raw_line=line,
                    timestamp=timestamp,
                    action=event_info[0],
                    status=d.get('level', 'Information'),
                    message=d.get('message', ''),
                    log_type='WINDOWS_EVENT',
                    line_number=line_number,
                    severity=event_info[1],
                    extra={
                        'event_id': event_id,
                        'source': d.get('source'),
                        'category': d.get('category')
                    }
                )
            except:
                pass
        
        return None


class IISParser:
    """Parser para IIS (Internet Information Services) logs."""
    
    # W3C Extended Log Format (padrão IIS)
    W3C_PATTERN = re.compile(
        r'^(?P<date>\d{4}-\d{2}-\d{2})\s+'
        r'(?P<time>\d{2}:\d{2}:\d{2})\s+'
        r'(?P<s_ip>\S+)\s+'
        r'(?P<cs_method>\S+)\s+'
        r'(?P<cs_uri_stem>\S+)\s+'
        r'(?P<cs_uri_query>\S+)\s+'
        r'(?P<s_port>\d+)\s+'
        r'(?P<cs_username>\S+)\s+'
        r'(?P<c_ip>\S+)\s+'
        r'(?P<cs_user_agent>\S+)\s+'
        r'(?P<cs_referer>\S+)\s+'
        r'(?P<sc_status>\d+)\s+'
        r'(?P<sc_substatus>\d+)\s+'
        r'(?P<sc_win32_status>\d+)\s+'
        r'(?P<time_taken>\d+)'
    )
    
    # Padrão simplificado
    SIMPLE_PATTERN = re.compile(
        r'^(?P<date>\d{4}-\d{2}-\d{2})\s+'
        r'(?P<time>\d{2}:\d{2}:\d{2})\s+'
        r'(?P<c_ip>\d+\.\d+\.\d+\.\d+)\s+'
        r'(?P<cs_method>\S+)\s+'
        r'(?P<cs_uri_stem>\S+)\s+'
        r'.*\s+(?P<sc_status>\d{3})\s+'
    )
    
    def parse(self, line: str, line_number: int = 0) -> Optional[ExtendedLogEntry]:
        """Parse linha de IIS log."""
        # Ignorar linhas de comentário
        if line.startswith('#'):
            return None
        
        # Tentar W3C completo
        match = self.W3C_PATTERN.match(line)
        if not match:
            match = self.SIMPLE_PATTERN.match(line)
        
        if match:
            d = match.groupdict()
            try:
                timestamp = datetime.strptime(
                    f"{d['date']} {d['time']}",
                    '%Y-%m-%d %H:%M:%S'
                )
                
                status_code = int(d.get('sc_status', 0))
                severity = 'INFO'
                if status_code >= 400:
                    severity = 'WARNING'
                if status_code >= 500:
                    severity = 'ERROR'
                
                return ExtendedLogEntry(
                    raw_line=line,
                    timestamp=timestamp,
                    source_ip=d.get('c_ip'),
                    user=d.get('cs_username', '-'),
                    action=d.get('cs_method'),
                    status=str(status_code),
                    message=f"{d.get('cs_method')} {d.get('cs_uri_stem')}",
                    log_type='IIS',
                    line_number=line_number,
                    target=d.get('cs_uri_stem'),
                    severity=severity,
                    extra={
                        'query': d.get('cs_uri_query'),
                        'user_agent': d.get('cs_user_agent'),
                        'time_taken': d.get('time_taken')
                    }
                )
            except:
                pass
        
        return None


class PostgreSQLParser:
    """Parser para PostgreSQL logs."""
    
    # Formato padrão PostgreSQL
    PG_PATTERN = re.compile(
        r'^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+'
        r'(?P<timezone>\S+)\s+'
        r'\[(?P<pid>\d+)\]\s+'
        r'(?P<user>\S+)@(?P<database>\S+)\s+'
        r'(?P<level>\S+):\s+'
        r'(?P<message>.*)$'
    )
    
    # Formato simplificado
    PG_SIMPLE = re.compile(
        r'^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+'
        r'(?P<level>LOG|ERROR|WARNING|FATAL|PANIC|DEBUG\d?):\s+'
        r'(?P<message>.*)$'
    )
    
    # Padrões suspeitos em queries
    SUSPICIOUS_PATTERNS = [
        (re.compile(r'(?i)DROP\s+(TABLE|DATABASE|INDEX)', re.IGNORECASE), 'DROP_OPERATION'),
        (re.compile(r'(?i)TRUNCATE\s+TABLE', re.IGNORECASE), 'TRUNCATE'),
        (re.compile(r'(?i)DELETE\s+FROM\s+\w+\s*$', re.IGNORECASE), 'DELETE_ALL'),
        (re.compile(r'(?i)pg_shadow|pg_authid', re.IGNORECASE), 'SYSTEM_TABLE_ACCESS'),
        (re.compile(r'(?i)COPY\s+.*\s+TO\s+PROGRAM', re.IGNORECASE), 'COPY_TO_PROGRAM'),
    ]
    
    def parse(self, line: str, line_number: int = 0) -> Optional[ExtendedLogEntry]:
        """Parse linha de PostgreSQL log."""
        match = self.PG_PATTERN.match(line) or self.PG_SIMPLE.match(line)
        
        if match:
            d = match.groupdict()
            try:
                timestamp = datetime.strptime(
                    d['timestamp'].split('.')[0],
                    '%Y-%m-%d %H:%M:%S'
                )
                
                level = d.get('level', 'LOG').upper()
                severity_map = {
                    'DEBUG': 'DEBUG', 'DEBUG1': 'DEBUG', 'DEBUG2': 'DEBUG',
                    'LOG': 'INFO', 'INFO': 'INFO', 'NOTICE': 'INFO',
                    'WARNING': 'WARNING', 'ERROR': 'ERROR',
                    'FATAL': 'CRITICAL', 'PANIC': 'CRITICAL'
                }
                severity = severity_map.get(level, 'INFO')
                
                # Verificar padrões suspeitos
                suspicious = []
                message = d.get('message', '')
                for pattern, name in self.SUSPICIOUS_PATTERNS:
                    if pattern.search(message):
                        suspicious.append(name)
                        severity = 'WARNING'
                
                return ExtendedLogEntry(
                    raw_line=line,
                    timestamp=timestamp,
                    user=d.get('user'),
                    status=level,
                    message=message,
                    log_type='POSTGRESQL',
                    line_number=line_number,
                    severity=severity,
                    extra={
                        'pid': d.get('pid'),
                        'database': d.get('database'),
                        'suspicious': suspicious if suspicious else None
                    }
                )
            except:
                pass
        
        return None


class MySQLParser:
    """Parser para MySQL logs."""
    
    # General query log
    GENERAL_PATTERN = re.compile(
        r'^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z?)\s+'
        r'(?P<thread_id>\d+)\s+'
        r'(?P<command_type>\S+)\s+'
        r'(?P<argument>.*)$'
    )
    
    # Error log
    ERROR_PATTERN = re.compile(
        r'^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z?)\s+'
        r'(?P<thread_id>\d+)\s+'
        r'\[(?P<level>\w+)\]\s+'
        r'(?:\[(?P<err_code>\S+)\]\s+)?'
        r'(?:\[(?P<subsystem>\S+)\]\s+)?'
        r'(?P<message>.*)$'
    )
    
    # Slow query log
    SLOW_PATTERN = re.compile(
        r'^#\s+Time:\s+(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})'
    )
    
    def parse(self, line: str, line_number: int = 0) -> Optional[ExtendedLogEntry]:
        """Parse linha de MySQL log."""
        # Tentar error log
        match = self.ERROR_PATTERN.match(line)
        if match:
            d = match.groupdict()
            try:
                timestamp = datetime.strptime(
                    d['timestamp'][:19],
                    '%Y-%m-%dT%H:%M:%S'
                )
                
                level = d.get('level', 'Note').capitalize()
                severity_map = {
                    'Note': 'INFO', 'Warning': 'WARNING', 'Error': 'ERROR', 'System': 'INFO'
                }
                
                return ExtendedLogEntry(
                    raw_line=line,
                    timestamp=timestamp,
                    status=level,
                    message=d.get('message', ''),
                    log_type='MYSQL_ERROR',
                    line_number=line_number,
                    severity=severity_map.get(level, 'INFO'),
                    extra={
                        'thread_id': d.get('thread_id'),
                        'error_code': d.get('err_code'),
                        'subsystem': d.get('subsystem')
                    }
                )
            except:
                pass
        
        # Tentar general query log
        match = self.GENERAL_PATTERN.match(line)
        if match:
            d = match.groupdict()
            try:
                timestamp = datetime.strptime(
                    d['timestamp'][:19],
                    '%Y-%m-%dT%H:%M:%S'
                )
                
                return ExtendedLogEntry(
                    raw_line=line,
                    timestamp=timestamp,
                    action=d.get('command_type'),
                    message=d.get('argument', ''),
                    log_type='MYSQL_QUERY',
                    line_number=line_number,
                    severity='INFO',
                    extra={'thread_id': d.get('thread_id')}
                )
            except:
                pass
        
        return None


class FirewallParser:
    """Parser para logs de Firewall (iptables, pf, Windows Firewall)."""
    
    # iptables (Linux)
    IPTABLES_PATTERN = re.compile(
        r'(?P<prefix>.*?)\s*'
        r'IN=(?P<in_iface>\S*)\s+'
        r'OUT=(?P<out_iface>\S*)\s+'
        r'(?:MAC=(?P<mac>\S+)\s+)?'
        r'SRC=(?P<src_ip>\d+\.\d+\.\d+\.\d+)\s+'
        r'DST=(?P<dst_ip>\d+\.\d+\.\d+\.\d+)\s+'
        r'.*?'
        r'PROTO=(?P<proto>\S+)\s+'
        r'(?:SPT=(?P<src_port>\d+)\s+)?'
        r'(?:DPT=(?P<dst_port>\d+)\s+)?'
    )
    
    # UFW (Ubuntu)
    UFW_PATTERN = re.compile(
        r'\[UFW\s+(?P<action>BLOCK|ALLOW|AUDIT)\]\s+'
        r'IN=(?P<in_iface>\S*)\s+'
        r'.*?'
        r'SRC=(?P<src_ip>\d+\.\d+\.\d+\.\d+)\s+'
        r'DST=(?P<dst_ip>\d+\.\d+\.\d+\.\d+)\s+'
        r'.*?'
        r'PROTO=(?P<proto>\S+)'
    )
    
    # Windows Firewall
    WIN_FW_PATTERN = re.compile(
        r'^(?P<date>\d{4}-\d{2}-\d{2})\s+'
        r'(?P<time>\d{2}:\d{2}:\d{2})\s+'
        r'(?P<action>\S+)\s+'
        r'(?P<proto>\S+)\s+'
        r'(?P<src_ip>\d+\.\d+\.\d+\.\d+)\s+'
        r'(?P<dst_ip>\d+\.\d+\.\d+\.\d+)\s+'
        r'(?P<src_port>\d+)\s+'
        r'(?P<dst_port>\d+)'
    )
    
    def parse(self, line: str, line_number: int = 0) -> Optional[ExtendedLogEntry]:
        """Parse linha de firewall log."""
        # UFW
        match = self.UFW_PATTERN.search(line)
        if match:
            d = match.groupdict()
            action = d.get('action', 'UNKNOWN')
            severity = 'WARNING' if action == 'BLOCK' else 'INFO'
            
            return ExtendedLogEntry(
                raw_line=line,
                timestamp=datetime.now(),  # UFW normalmente usa syslog timestamp
                source_ip=d.get('src_ip'),
                target=d.get('dst_ip'),
                action=action,
                message=f"{action} {d.get('proto')} from {d.get('src_ip')} to {d.get('dst_ip')}",
                log_type='FIREWALL_UFW',
                line_number=line_number,
                severity=severity,
                extra={
                    'protocol': d.get('proto'),
                    'interface': d.get('in_iface')
                }
            )
        
        # iptables
        match = self.IPTABLES_PATTERN.search(line)
        if match:
            d = match.groupdict()
            return ExtendedLogEntry(
                raw_line=line,
                timestamp=datetime.now(),
                source_ip=d.get('src_ip'),
                target=d.get('dst_ip'),
                action='LOG',
                message=f"{d.get('proto')} {d.get('src_ip')}:{d.get('src_port')} -> {d.get('dst_ip')}:{d.get('dst_port')}",
                log_type='FIREWALL_IPTABLES',
                line_number=line_number,
                severity='WARNING',
                extra={
                    'protocol': d.get('proto'),
                    'src_port': d.get('src_port'),
                    'dst_port': d.get('dst_port'),
                    'in_interface': d.get('in_iface'),
                    'out_interface': d.get('out_iface')
                }
            )
        
        # Windows Firewall
        match = self.WIN_FW_PATTERN.match(line)
        if match:
            d = match.groupdict()
            try:
                timestamp = datetime.strptime(
                    f"{d['date']} {d['time']}",
                    '%Y-%m-%d %H:%M:%S'
                )
                action = d.get('action', '').upper()
                severity = 'WARNING' if action in ['DROP', 'DENY'] else 'INFO'
                
                return ExtendedLogEntry(
                    raw_line=line,
                    timestamp=timestamp,
                    source_ip=d.get('src_ip'),
                    target=d.get('dst_ip'),
                    action=action,
                    message=f"{action} {d.get('proto')} {d.get('src_ip')}:{d.get('src_port')} -> {d.get('dst_ip')}:{d.get('dst_port')}",
                    log_type='FIREWALL_WINDOWS',
                    line_number=line_number,
                    severity=severity,
                    extra={
                        'protocol': d.get('proto'),
                        'src_port': d.get('src_port'),
                        'dst_port': d.get('dst_port')
                    }
                )
            except:
                pass
        
        return None


class DockerParser:
    """Parser para logs de Docker/Container."""
    
    # JSON log format (docker default)
    JSON_PATTERN = re.compile(r'^\{.*\}$')
    
    # Docker compose format
    COMPOSE_PATTERN = re.compile(
        r'^(?P<container>\S+)\s+\|\s+'
        r'(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z?)\s+'
        r'(?P<message>.*)$'
    )
    
    def parse(self, line: str, line_number: int = 0) -> Optional[ExtendedLogEntry]:
        """Parse linha de Docker log."""
        # JSON format
        if self.JSON_PATTERN.match(line):
            try:
                data = json.loads(line)
                timestamp = None
                if 'time' in data:
                    timestamp = datetime.fromisoformat(data['time'].replace('Z', '+00:00'))
                
                return ExtendedLogEntry(
                    raw_line=line,
                    timestamp=timestamp,
                    message=data.get('log', data.get('message', '')),
                    log_type='DOCKER',
                    line_number=line_number,
                    severity=data.get('level', 'INFO').upper(),
                    extra={
                        'stream': data.get('stream'),
                        'container': data.get('container_name'),
                        'attrs': data.get('attrs')
                    }
                )
            except json.JSONDecodeError:
                pass
        
        # Compose format
        match = self.COMPOSE_PATTERN.match(line)
        if match:
            d = match.groupdict()
            try:
                timestamp = datetime.fromisoformat(d['timestamp'].replace('Z', '+00:00'))
            except:
                timestamp = None
            
            return ExtendedLogEntry(
                raw_line=line,
                timestamp=timestamp,
                message=d.get('message', ''),
                log_type='DOCKER_COMPOSE',
                line_number=line_number,
                severity='INFO',
                extra={'container': d.get('container')}
            )
        
        return None


class ExtendedLogParser:
    """Parser unificado para todos os formatos estendidos."""
    
    def __init__(self):
        self.parsers = {
            'windows': WindowsEventParser(),
            'iis': IISParser(),
            'postgresql': PostgreSQLParser(),
            'mysql': MySQLParser(),
            'firewall': FirewallParser(),
            'docker': DockerParser(),
        }
        
        self.stats = {
            'total_lines': 0,
            'parsed_lines': 0,
            'by_type': {}
        }
    
    def detect_format(self, line: str) -> Optional[str]:
        """Deteta formato da linha."""
        # Verificar cada parser
        for name, parser in self.parsers.items():
            if parser.parse(line):
                return name
        return None
    
    def parse_line(self, line: str, line_number: int = 0) -> Optional[ExtendedLogEntry]:
        """Parse linha com deteção automática."""
        self.stats['total_lines'] += 1
        
        for name, parser in self.parsers.items():
            result = parser.parse(line, line_number)
            if result:
                self.stats['parsed_lines'] += 1
                self.stats['by_type'][result.log_type] = self.stats['by_type'].get(result.log_type, 0) + 1
                return result
        
        return None
    
    def get_supported_formats(self) -> List[str]:
        """Retorna formatos suportados."""
        return [
            'Windows Event Log (EVTX texto)',
            'IIS W3C Extended',
            'PostgreSQL',
            'MySQL General/Error',
            'Firewall (iptables, UFW, Windows)',
            'Docker/Container JSON'
        ]
    
    def get_stats(self) -> Dict:
        """Retorna estatísticas."""
        return self.stats.copy()


# Teste
if __name__ == "__main__":
    print("🔧 Teste dos Extended Parsers")
    print("-" * 50)
    
    parser = ExtendedLogParser()
    
    test_lines = [
        # Windows Event
        '01/29/2024 14:30:45 PM Error Microsoft-Windows-Security-Auditing 4625 Logon An account failed to log on',
        # IIS
        '2024-01-29 14:30:45 192.168.1.1 GET /api/users - 80 - 10.0.0.100 Mozilla/5.0 - 200 0 0 125',
        # PostgreSQL
        '2024-01-29 14:30:45.123 UTC [1234] postgres@mydb ERROR:  syntax error at or near "DROP"',
        # iptables
        'Jan 29 14:30:45 server kernel: [UFW BLOCK] IN=eth0 OUT= MAC=... SRC=10.0.0.100 DST=192.168.1.1 PROTO=TCP',
        # Docker
        '{"log":"2024-01-29T14:30:45.123Z INFO Starting application\\n","stream":"stdout","time":"2024-01-29T14:30:45.123456789Z"}',
    ]
    
    print("📝 Parsing linhas de teste:")
    for line in test_lines:
        entry = parser.parse_line(line)
        if entry:
            print(f"\n  Tipo: {entry.log_type}")
            print(f"  Severidade: {entry.severity}")
            print(f"  Mensagem: {entry.message[:50]}...")
    
    print(f"\n📊 Estatísticas: {parser.get_stats()}")
    print(f"\n📋 Formatos suportados: {parser.get_supported_formats()}")
    print("✅ Teste concluído!")
