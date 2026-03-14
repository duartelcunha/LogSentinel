"""
Log Sentinel v2.0 - Log Parser
===============================
Parser avançado de ficheiros de log multi-formato.

Author: Duarte Cunha (Nº 2024271)
ISTEC - Instituto Superior de Tecnologias Avançadas de Lisboa
Ano Letivo: 2025/2026
"""

import re
import os
from datetime import datetime
from typing import List, Dict, Optional, Generator, Tuple
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class LogEntry:
    """Estrutura de dados para uma entrada de log parseada."""
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
    extra: Dict = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        """Converte para dicionário."""
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
            'extra': self.extra
        }


class LogParser:
    """
    Parser de logs multi-formato avançado.
    
    Formatos suportados:
    - Syslog (RFC 3164/5424)
    - Auth.log (Linux)
    - Apache/Nginx access/error logs
    - Windows Event Logs (texto)
    - JSON logs
    - Logs genéricos
    """
    
    # === Padrões de IP ===
    IP_PATTERN = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    IPV6_PATTERN = r'([a-fA-F0-9:]+:+[a-fA-F0-9]+)'
    
    # === Padrões de Timestamp ===
    TIMESTAMP_PATTERNS = [
        (r'([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', '%b %d %H:%M:%S'),
        (r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})', '%Y-%m-%d %H:%M:%S'),
        (r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})', '%Y-%m-%dT%H:%M:%S'),
        (r'(\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2})', '%d/%b/%Y:%H:%M:%S'),
        (r'\[(\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2})', '%d/%b/%Y:%H:%M:%S'),
        (r'(\d{2}-\d{2}-\d{4}\s+\d{2}:\d{2}:\d{2})', '%d-%m-%Y %H:%M:%S'),
        (r'(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})', '%Y/%m/%d %H:%M:%S'),
    ]
    
    # === Padrão Syslog ===
    SYSLOG_PATTERN = re.compile(
        r'^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
        r'(?P<hostname>\S+)\s+'
        r'(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s+'
        r'(?P<message>.*)$'
    )
    
    # === Padrões Auth ===
    AUTH_PATTERNS = {
        'failed_password': re.compile(
            r'Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)'
        ),
        'accepted_password': re.compile(
            r'Accepted password for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)'
        ),
        'invalid_user': re.compile(
            r'Invalid user (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)'
        ),
        'session_opened': re.compile(r'session opened for user (?P<user>\S+)'),
        'session_closed': re.compile(r'session closed for user (?P<user>\S+)'),
        'sudo': re.compile(r'(?P<user>\S+)\s*:.*COMMAND=(?P<command>.+)$'),
        'connection_closed': re.compile(
            r'Connection closed by (?:authenticating user )?(?P<user>\S+)?\s*(?P<ip>\d+\.\d+\.\d+\.\d+)?'
        ),
        'publickey_accepted': re.compile(
            r'Accepted publickey for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)'
        ),
    }
    
    # === Padrão Web Access ===
    WEB_ACCESS_PATTERN = re.compile(
        r'^(?P<ip>\d+\.\d+\.\d+\.\d+)\s+'
        r'(?P<ident>\S+)\s+'
        r'(?P<user>\S+)\s+'
        r'\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<method>\S+)\s+(?P<url>\S+)\s+(?P<protocol>[^"]+)"\s+'
        r'(?P<status>\d+)\s+'
        r'(?P<size>\d+|-)\s*'
        r'(?:"(?P<referer>[^"]*)"\s*)?'
        r'(?:"(?P<user_agent>[^"]*)")?'
    )
    
    # === Padrão Web Error ===
    WEB_ERROR_PATTERN = re.compile(
        r'^\[(?P<timestamp>[^\]]+)\]\s+'
        r'\[(?:(?P<module>\w+):)?(?P<level>\w+)\]\s+'
        r'(?:\[pid\s+(?P<pid>\d+)(?::tid\s+\d+)?\]\s+)?'
        r'(?:\[client\s+(?P<ip>\d+\.\d+\.\d+\.\d+)(?::\d+)?\]\s+)?'
        r'(?P<message>.*)$'
    )
    
    # === Padrões de Ataque ===
    ATTACK_PATTERNS = {
        'SQL_INJECTION': [
            re.compile(r"(?i)(\bunion\b.*\bselect\b|\bselect\b.*\bfrom\b.*\bwhere\b)"),
            re.compile(r"(?i)('|\")\s*(or|and)\s+['\"]?\d+['\"]?\s*[=<>]"),
            re.compile(r"(?i)\b(drop|delete|insert|update|alter|truncate)\s+(table|database|into)\b"),
            re.compile(r"(?i)(\bexec\b|\bexecute\b)\s*\("),
            re.compile(r"(?i)(1\s*=\s*1|'='|'\s*or\s*'|or\s+1\s*=\s*1)"),
            re.compile(r"(?i)(;|\-\-|/\*|\*/|@@|char\s*\(|nchar\s*\()"),
            re.compile(r"(?i)information_schema|sysobjects|syscolumns"),
            # Novos padrões mais abrangentes
            re.compile(r"'\s*or\s*'", re.IGNORECASE),  # ' OR '
            re.compile(r"'\s*=\s*'", re.IGNORECASE),   # '='
            re.compile(r"or\s+'[^']*'\s*=\s*'", re.IGNORECASE),  # or '1'='1
            re.compile(r"\d+\s*or\s+\d+\s*=\s*\d+", re.IGNORECASE),  # 1 or 1=1
            re.compile(r"'\s*;\s*--", re.IGNORECASE),  # '; --
            re.compile(r"admin'\s*--", re.IGNORECASE),  # admin'--
        ],
        'XSS': [
            re.compile(r"(?i)<script[^>]*>"),
            re.compile(r"(?i)javascript\s*:"),
            re.compile(r"(?i)on(load|error|click|mouse|focus|blur|change|submit|key)\s*="),
            re.compile(r"(?i)<iframe[^>]*>"),
            re.compile(r"(?i)document\.(cookie|location|write|domain)"),
            re.compile(r"(?i)<img[^>]+on\w+\s*="),
            re.compile(r"(?i)eval\s*\("),
            re.compile(r"(?i)expression\s*\("),
        ],
        'PATH_TRAVERSAL': [
            re.compile(r"\.\./"),
            re.compile(r"\.\.\\"),
            re.compile(r"%2e%2e[%/\\]", re.IGNORECASE),
            re.compile(r"(?i)/etc/(passwd|shadow|hosts|group|sudoers)"),
            re.compile(r"(?i)/proc/(self|version|cmdline|environ)"),
            re.compile(r"(?i)c:(\\|/)(windows|winnt|boot\.ini)", re.IGNORECASE),
            re.compile(r"(?i)/var/log/"),
        ],
        'COMMAND_INJECTION': [
            re.compile(r"[;&|`]"),
            re.compile(r"\$\([^)]+\)"),
            re.compile(r"(?i)\b(wget|curl|nc|netcat|bash|sh|cmd|powershell|python|perl|ruby)\b.*[;&|]"),
            re.compile(r"(?i)/bin/(bash|sh|cat|ls|rm|chmod|chown)"),
            re.compile(r"(?i)>(>)?(\s*/dev/null|\s*\d+)?"),
        ],
        'SCANNER': [
            re.compile(r"(?i)(nikto|nmap|sqlmap|dirbuster|gobuster|wpscan|acunetix|nessus|burp)"),
            re.compile(r"(?i)/(\.git|\.svn|\.env|\.htaccess|\.htpasswd|\.ds_store|\.aws)"),
            re.compile(r"(?i)/wp-(admin|login|includes|content|config)"),
            re.compile(r"(?i)/(phpmyadmin|phpinfo|adminer|server-status|server-info)"),
            re.compile(r"(?i)/(backup|db|sql|dump|config)\.(zip|tar|gz|sql|bak|old)$"),
            re.compile(r"(?i)/robots\.txt|/sitemap\.xml"),
        ],
        'LFI_RFI': [
            re.compile(r"(?i)(file|php|zip|data|expect|input|phar)://"),
            re.compile(r"(?i)\?.*=.*\.(php|asp|jsp|txt|log|ini|conf)"),
            re.compile(r"(?i)include\s*\(|require\s*\(|include_once|require_once"),
        ],
        'XXE': [
            re.compile(r"(?i)<!DOCTYPE[^>]*\["),
            re.compile(r"(?i)<!ENTITY"),
            re.compile(r"(?i)SYSTEM\s+['\"]"),
        ],
    }
    
    def __init__(self):
        """Inicializa o parser."""
        self.stats = {
            'total_lines': 0,
            'parsed_lines': 0,
            'failed_lines': 0,
            'by_type': {},
            'attack_indicators': {}
        }
    
    def parse_file(self, filepath: str, callback=None) -> Generator[LogEntry, None, None]:
        """
        Parse um ficheiro de log completo.
        
        Args:
            filepath: Caminho para o ficheiro
            callback: Função callback para progresso (linha_atual, total)
        
        Yields:
            LogEntry para cada linha parseada
        """
        filepath = Path(filepath)
        if not filepath.exists():
            raise FileNotFoundError(f"Ficheiro não encontrado: {filepath}")
        
        filename = filepath.name
        total_lines = sum(1 for _ in open(filepath, 'r', encoding='utf-8', errors='ignore'))
        
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                
                self.stats['total_lines'] += 1
                
                if callback and line_num % 100 == 0:
                    callback(line_num, total_lines)
                
                try:
                    entry = self.parse_line(line, line_num, filename)
                    if entry:
                        self.stats['parsed_lines'] += 1
                        log_type = entry.log_type
                        self.stats['by_type'][log_type] = self.stats['by_type'].get(log_type, 0) + 1
                        yield entry
                except Exception as e:
                    self.stats['failed_lines'] += 1
    
    def parse_line(self, line: str, line_number: int = 0, filename: str = "") -> Optional[LogEntry]:
        """Parse uma única linha de log."""
        entry = LogEntry(raw_line=line, line_number=line_number)
        
        # Tentar JSON primeiro
        if line.startswith('{'):
            result = self._parse_json(line, entry)
            if result:
                return result
        
        # Web Access Log
        match = self.WEB_ACCESS_PATTERN.match(line)
        if match:
            return self._parse_web_access(match, entry)
        
        # Web Error Log
        match = self.WEB_ERROR_PATTERN.match(line)
        if match:
            return self._parse_web_error(match, entry)
        
        # Syslog/Auth Log
        match = self.SYSLOG_PATTERN.match(line)
        if match:
            return self._parse_syslog(match, entry, filename)
        
        # Fallback genérico
        return self._parse_generic(line, entry)
    
    def _parse_json(self, line: str, entry: LogEntry) -> Optional[LogEntry]:
        """Parse logs em formato JSON."""
        try:
            import json
            data = json.loads(line)
            
            entry.log_type = "JSON"
            entry.message = data.get('message', data.get('msg', str(data)))
            entry.source_ip = data.get('ip', data.get('source_ip', data.get('client_ip')))
            entry.user = data.get('user', data.get('username'))
            entry.status = str(data.get('status', data.get('level', '')))
            
            # Timestamp
            ts = data.get('timestamp', data.get('@timestamp', data.get('time')))
            if ts:
                entry.timestamp = self._parse_timestamp(str(ts))
            
            entry.extra = data
            entry.extra['attack_indicators'] = self._detect_attack_patterns(entry.message)
            
            return entry
        except:
            return None
    
    def _parse_web_access(self, match: re.Match, entry: LogEntry) -> LogEntry:
        """Parse log de acesso web."""
        data = match.groupdict()
        
        entry.log_type = "WEB_ACCESS"
        entry.source_ip = data.get('ip')
        entry.user = data.get('user') if data.get('user') != '-' else None
        entry.status = data.get('status')
        entry.action = f"{data.get('method')} {data.get('url')}"
        entry.target = data.get('url')
        entry.message = entry.raw_line
        entry.timestamp = self._parse_timestamp(data.get('timestamp', ''))
        
        entry.extra = {
            'method': data.get('method'),
            'url': data.get('url'),
            'protocol': data.get('protocol'),
            'size': data.get('size'),
            'referer': data.get('referer'),
            'user_agent': data.get('user_agent'),
            'status_code': int(data.get('status', 0)),
        }
        
        # Detetar ataques - usar URL completo e linha raw para máxima deteção
        url = data.get('url', '')
        user_agent = data.get('user_agent', '')
        raw_line = entry.raw_line
        entry.extra['attack_indicators'] = self._detect_attack_patterns(f"{url} {user_agent} {raw_line}")
        
        return entry
    
    def _parse_web_error(self, match: re.Match, entry: LogEntry) -> LogEntry:
        """Parse log de erro web."""
        data = match.groupdict()
        
        entry.log_type = "WEB_ERROR"
        entry.source_ip = data.get('ip')
        entry.message = data.get('message', '')
        entry.status = data.get('level', 'error').upper()
        entry.timestamp = self._parse_timestamp(data.get('timestamp', ''))
        
        entry.extra = {
            'level': data.get('level'),
            'module': data.get('module'),
            'pid': data.get('pid'),
        }
        
        entry.extra['attack_indicators'] = self._detect_attack_patterns(entry.message)
        
        return entry
    
    def _parse_syslog(self, match: re.Match, entry: LogEntry, filename: str) -> LogEntry:
        """Parse log Syslog/Auth."""
        data = match.groupdict()
        
        message = data.get('message', '')
        process = data.get('process', '').lower()
        
        # Determinar tipo
        if 'auth' in filename.lower() or any(x in process for x in ['sshd', 'sudo', 'pam', 'login']):
            entry.log_type = "AUTH"
            self._parse_auth_message(message, entry)
        else:
            entry.log_type = "SYSLOG"
        
        entry.message = message
        entry.timestamp = self._parse_timestamp(data.get('timestamp', ''))
        
        entry.extra = {
            'hostname': data.get('hostname'),
            'process': data.get('process'),
            'pid': data.get('pid'),
        }
        
        entry.extra['attack_indicators'] = self._detect_attack_patterns(message)
        
        return entry
    
    def _parse_auth_message(self, message: str, entry: LogEntry) -> None:
        """Extrai informação de logs de autenticação."""
        for pattern_name, pattern in self.AUTH_PATTERNS.items():
            match = pattern.search(message)
            if match:
                data = match.groupdict()
                entry.user = data.get('user')
                entry.source_ip = data.get('ip') or entry.source_ip
                entry.action = pattern_name
                
                if 'failed' in pattern_name or 'invalid' in pattern_name:
                    entry.status = 'FAILED'
                elif 'accepted' in pattern_name or 'opened' in pattern_name:
                    entry.status = 'SUCCESS'
                
                entry.extra['auth_pattern'] = pattern_name
                if 'command' in data:
                    entry.extra['command'] = data['command']
                break
    
    def _parse_generic(self, line: str, entry: LogEntry) -> LogEntry:
        """Parse genérico para logs não reconhecidos."""
        entry.log_type = "GENERIC"
        entry.message = line
        
        # Extrair IP
        ip_match = re.search(self.IP_PATTERN, line)
        if ip_match:
            entry.source_ip = ip_match.group(1)
        
        # Extrair timestamp
        for pattern, fmt in self.TIMESTAMP_PATTERNS:
            ts_match = re.search(pattern, line)
            if ts_match:
                entry.timestamp = self._parse_timestamp(ts_match.group(1))
                break
        
        # Detetar ataques
        entry.extra['attack_indicators'] = self._detect_attack_patterns(line)
        
        return entry
    
    def _parse_timestamp(self, ts_str: str) -> Optional[datetime]:
        """Tenta parsear uma string de timestamp."""
        if not ts_str:
            return None
        
        ts_str = ts_str.strip('[]')
        
        for pattern, fmt in self.TIMESTAMP_PATTERNS:
            try:
                match = re.match(pattern, ts_str)
                if match:
                    dt = datetime.strptime(match.group(1), fmt)
                    if dt.year == 1900:
                        dt = dt.replace(year=datetime.now().year)
                    return dt
            except ValueError:
                continue
        
        return None
    
    def _detect_attack_patterns(self, text: str) -> List[str]:
        """Deteta padrões de ataque no texto."""
        detected = []
        
        for attack_type, patterns in self.ATTACK_PATTERNS.items():
            for pattern in patterns:
                if pattern.search(text):
                    if attack_type not in detected:
                        detected.append(attack_type)
                        # Atualizar estatísticas
                        self.stats['attack_indicators'][attack_type] = \
                            self.stats['attack_indicators'].get(attack_type, 0) + 1
                    break
        
        return detected
    
    def get_stats(self) -> Dict:
        """Retorna estatísticas do parsing."""
        return self.stats.copy()
    
    def reset_stats(self) -> None:
        """Reset das estatísticas."""
        self.stats = {
            'total_lines': 0,
            'parsed_lines': 0,
            'failed_lines': 0,
            'by_type': {},
            'attack_indicators': {}
        }


# Teste do módulo
if __name__ == "__main__":
    print("🔧 Teste do LogParser v2")
    print("-" * 40)
    
    parser = LogParser()
    
    test_lines = [
        "Jan 29 14:30:45 server sshd[1234]: Failed password for admin from 192.168.1.100 port 22",
        '192.168.1.50 - - [29/Jan/2024:15:30:45 +0000] "GET /admin?id=1 OR 1=1 HTTP/1.1" 200 1234',
        '10.0.0.100 - - [29/Jan/2024:15:31:00 +0000] "GET /../../../etc/passwd HTTP/1.1" 403 500',
        '[Mon Jan 29 15:30:45 2024] [error] [client 192.168.1.75] File not found',
    ]
    
    print("📝 Parsing linhas de teste:")
    for line in test_lines:
        entry = parser.parse_line(line)
        if entry:
            print(f"\n  Tipo: {entry.log_type}")
            print(f"  IP: {entry.source_ip}")
            if entry.extra.get('attack_indicators'):
                print(f"  ⚠️ Ataques: {entry.extra['attack_indicators']}")
    
    print(f"\n📊 Estatísticas: {parser.get_stats()}")
    print("✅ Teste concluído!")
