"""
Log Sentinel v2.0 - Plugin System
==================================
Sistema de plugins para deteção customizada.

Author: Duarte Cunha (Nº 2024271)
ISTEC - Instituto Superior de Tecnologias Avançadas de Lisboa
Ano Letivo: 2025/2026

Este sistema permite:
- Criar plugins de deteção customizados
- Carregar plugins dinamicamente
- Gerir plugins através da interface
"""

import os
import re
import json
import importlib.util
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Dict, Optional, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class PluginInfo:
    """Informações de um plugin."""
    id: str
    name: str
    version: str
    author: str
    description: str
    enabled: bool = True
    config: Dict = field(default_factory=dict)
    filepath: Optional[str] = None


@dataclass
class DetectionResult:
    """Resultado de uma deteção de plugin."""
    detected: bool
    anomaly_type: str = "PLUGIN_DETECTED"
    severity: str = "MEDIUM"
    detail: str = ""
    score: float = 0.5
    evidence: List[str] = field(default_factory=list)
    extra: Dict = field(default_factory=dict)


class BaseDetectionPlugin(ABC):
    """
    Classe base para plugins de deteção.
    
    Para criar um plugin, herde desta classe e implemente o método detect().
    
    Exemplo:
    ```python
    class MyPlugin(BaseDetectionPlugin):
        name = "Meu Plugin"
        version = "1.0"
        author = "Autor"
        description = "Descrição do plugin"
        
        def detect(self, entry):
            # Lógica de deteção
            if "suspicious" in entry.get('message', ''):
                return DetectionResult(
                    detected=True,
                    anomaly_type="MY_DETECTION",
                    severity="HIGH",
                    detail="Padrão suspeito detetado"
                )
            return DetectionResult(detected=False)
    ```
    """
    
    # Metadados (override nas subclasses)
    name: str = "Base Plugin"
    version: str = "1.0"
    author: str = "Unknown"
    description: str = "No description"
    
    # Configuração padrão
    default_config: Dict = {}
    
    def __init__(self, config: Dict = None):
        """
        Inicializa o plugin.
        
        Args:
            config: Configuração customizada (merge com default_config)
        """
        self.config = {**self.default_config}
        if config:
            self.config.update(config)
        self.enabled = True
        self._stats = {'detections': 0, 'entries_processed': 0}
    
    @abstractmethod
    def detect(self, entry: Dict) -> DetectionResult:
        """
        Método principal de deteção.
        
        Args:
            entry: Dicionário com dados da entrada de log
                   Campos comuns: message, source_ip, timestamp, 
                   raw_line, user, status, url, user_agent
        
        Returns:
            DetectionResult com o resultado da análise
        """
        pass
    
    def process(self, entry: Dict) -> Optional[DetectionResult]:
        """
        Processa uma entrada (com tracking de estatísticas).
        
        Args:
            entry: Entrada de log
            
        Returns:
            DetectionResult se detetado, None caso contrário
        """
        if not self.enabled:
            return None
        
        self._stats['entries_processed'] += 1
        
        result = self.detect(entry)
        
        if result.detected:
            self._stats['detections'] += 1
            return result
        
        return None
    
    def get_info(self) -> PluginInfo:
        """Retorna informações do plugin."""
        return PluginInfo(
            id=self.__class__.__name__,
            name=self.name,
            version=self.version,
            author=self.author,
            description=self.description,
            enabled=self.enabled,
            config=self.config
        )
    
    def get_stats(self) -> Dict:
        """Retorna estatísticas do plugin."""
        return self._stats.copy()
    
    def reset_stats(self) -> None:
        """Reset das estatísticas."""
        self._stats = {'detections': 0, 'entries_processed': 0}
    
    def configure(self, config: Dict) -> None:
        """Atualiza configuração."""
        self.config.update(config)


class PluginManager:
    """
    Gestor de plugins.
    
    Carrega, gere e executa plugins de deteção.
    """
    
    def __init__(self, plugins_dir: str = "src/plugins"):
        """
        Inicializa o gestor.
        
        Args:
            plugins_dir: Diretório com ficheiros de plugins
        """
        self.plugins_dir = Path(plugins_dir)
        self.plugins: Dict[str, BaseDetectionPlugin] = {}
        self._load_builtin_plugins()
    
    def _load_builtin_plugins(self) -> None:
        """Carrega plugins built-in."""
        # Adicionar plugins padrão
        builtin_plugins = [
            APIAbusePlugin(),
            SensitiveDataPlugin(),
            AnomalousTimePlugin(),
        ]
        
        for plugin in builtin_plugins:
            self.register(plugin)
    
    def register(self, plugin: BaseDetectionPlugin) -> None:
        """
        Regista um plugin.
        
        Args:
            plugin: Instância do plugin
        """
        plugin_id = plugin.__class__.__name__
        self.plugins[plugin_id] = plugin
    
    def unregister(self, plugin_id: str) -> bool:
        """
        Remove um plugin.
        
        Args:
            plugin_id: ID do plugin
            
        Returns:
            True se removido
        """
        if plugin_id in self.plugins:
            del self.plugins[plugin_id]
            return True
        return False
    
    def load_from_file(self, filepath: str) -> Optional[str]:
        """
        Carrega plugin de um ficheiro Python.
        
        Args:
            filepath: Caminho para o ficheiro .py
            
        Returns:
            ID do plugin carregado ou None
        """
        filepath = Path(filepath)
        if not filepath.exists():
            raise FileNotFoundError(f"Plugin não encontrado: {filepath}")
        
        try:
            spec = importlib.util.spec_from_file_location(
                filepath.stem, filepath
            )
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # Procurar classes que herdam de BaseDetectionPlugin
            for name in dir(module):
                obj = getattr(module, name)
                if (isinstance(obj, type) and 
                    issubclass(obj, BaseDetectionPlugin) and 
                    obj is not BaseDetectionPlugin):
                    
                    plugin = obj()
                    plugin_info = plugin.get_info()
                    plugin_info.filepath = str(filepath)
                    self.register(plugin)
                    return plugin.__class__.__name__
            
            return None
            
        except Exception as e:
            print(f"Erro ao carregar plugin: {e}")
            return None
    
    def load_from_directory(self) -> List[str]:
        """
        Carrega todos os plugins do diretório.
        
        Returns:
            Lista de IDs carregados
        """
        loaded = []
        
        if not self.plugins_dir.exists():
            self.plugins_dir.mkdir(parents=True, exist_ok=True)
            return loaded
        
        for filepath in self.plugins_dir.glob("*.py"):
            if filepath.name.startswith("_"):
                continue
            
            try:
                plugin_id = self.load_from_file(filepath)
                if plugin_id:
                    loaded.append(plugin_id)
            except Exception as e:
                print(f"Erro ao carregar {filepath}: {e}")
        
        return loaded
    
    def process_entry(self, entry: Dict) -> List[DetectionResult]:
        """
        Processa entrada com todos os plugins ativos.
        
        Args:
            entry: Entrada de log
            
        Returns:
            Lista de deteções
        """
        results = []
        
        for plugin in self.plugins.values():
            if plugin.enabled:
                result = plugin.process(entry)
                if result:
                    result.extra['plugin_id'] = plugin.__class__.__name__
                    result.extra['plugin_name'] = plugin.name
                    results.append(result)
        
        return results
    
    def get_plugins(self) -> List[PluginInfo]:
        """Retorna informações de todos os plugins."""
        return [p.get_info() for p in self.plugins.values()]
    
    def list_plugins(self) -> List[Dict]:
        """Lista todos os plugins com informações básicas."""
        return [
            {
                'name': p.name,
                'id': p.__class__.__name__,
                'version': p.version,
                'author': p.author,
                'description': p.description,
                'enabled': p.enabled
            }
            for p in self.plugins.values()
        ]
    
    def run_plugin(self, plugin_id: str, entry) -> Optional[Any]:
        """
        Executa um plugin específico numa entrada.
        
        Args:
            plugin_id: ID do plugin
            entry: Entrada de log (LogEntry ou dict)
            
        Returns:
            Resultado da deteção ou None
        """
        if plugin_id not in self.plugins:
            return None
        
        plugin = self.plugins[plugin_id]
        if not plugin.enabled:
            return None
        
        # Converter LogEntry para dict se necessário
        if hasattr(entry, 'to_dict'):
            entry_dict = entry.to_dict()
        elif hasattr(entry, '__dict__'):
            entry_dict = vars(entry)
        else:
            entry_dict = entry
        
        return plugin.process(entry_dict)
    
    def enable_plugin(self, plugin_id: str) -> bool:
        """Ativa um plugin."""
        if plugin_id in self.plugins:
            self.plugins[plugin_id].enabled = True
            return True
        return False
    
    def disable_plugin(self, plugin_id: str) -> bool:
        """Desativa um plugin."""
        if plugin_id in self.plugins:
            self.plugins[plugin_id].enabled = False
            return True
        return False
    
    def configure_plugin(self, plugin_id: str, config: Dict) -> bool:
        """Configura um plugin."""
        if plugin_id in self.plugins:
            self.plugins[plugin_id].configure(config)
            return True
        return False
    
    def get_stats(self) -> Dict[str, Dict]:
        """Retorna estatísticas de todos os plugins."""
        return {
            plugin_id: plugin.get_stats()
            for plugin_id, plugin in self.plugins.items()
        }


# === Built-in Plugins ===

class APIAbusePlugin(BaseDetectionPlugin):
    """Deteta abuso de APIs."""
    
    name = "API Abuse Detector"
    version = "1.0"
    author = "Log Sentinel"
    description = "Deteta padrões de abuso em endpoints de API"
    
    default_config = {
        'api_patterns': ['/api/', '/v1/', '/v2/', '/graphql'],
        'abuse_threshold': 50,  # Requests por minuto
    }
    
    def __init__(self, config: Dict = None):
        super().__init__(config)
        self._request_counts: Dict[str, List[datetime]] = {}
    
    def detect(self, entry: Dict) -> DetectionResult:
        url = entry.get('url', '') or entry.get('target', '')
        ip = entry.get('source_ip', '') or entry.get('ip', '')
        
        # Verificar se é request de API
        is_api = any(p in url for p in self.config['api_patterns'])
        
        if not is_api or not ip:
            return DetectionResult(detected=False)
        
        # Contar requests
        now = datetime.now()
        if ip not in self._request_counts:
            self._request_counts[ip] = []
        
        self._request_counts[ip].append(now)
        
        # Limpar antigos (> 1 minuto)
        from datetime import timedelta
        cutoff = now - timedelta(minutes=1)
        self._request_counts[ip] = [t for t in self._request_counts[ip] if t > cutoff]
        
        count = len(self._request_counts[ip])
        
        if count >= self.config['abuse_threshold']:
            self._request_counts[ip] = []  # Reset
            return DetectionResult(
                detected=True,
                anomaly_type="API_ABUSE",
                severity="HIGH",
                detail=f"Abuso de API: {count} requests/min de {ip}",
                score=min(1.0, count / 100),
                evidence=[entry.get('raw_line', '')],
                extra={'requests_per_minute': count, 'endpoint': url}
            )
        
        return DetectionResult(detected=False)


class SensitiveDataPlugin(BaseDetectionPlugin):
    """Deteta exposição de dados sensíveis."""
    
    name = "Sensitive Data Detector"
    version = "1.0"
    author = "Log Sentinel"
    description = "Deteta tentativas de acesso a dados sensíveis"
    
    default_config = {
        'sensitive_patterns': [
            r'password[=:]',
            r'api[_-]?key[=:]',
            r'secret[=:]',
            r'token[=:]',
            r'credit[_-]?card',
            r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',  # Credit card
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
        ]
    }
    
    def __init__(self, config: Dict = None):
        super().__init__(config)
        self._patterns = [
            re.compile(p, re.IGNORECASE) 
            for p in self.config['sensitive_patterns']
        ]
    
    def detect(self, entry: Dict) -> DetectionResult:
        text = entry.get('raw_line', '') or entry.get('message', '')
        url = entry.get('url', '') or ''
        
        full_text = f"{text} {url}"
        
        for pattern in self._patterns:
            match = pattern.search(full_text)
            if match:
                return DetectionResult(
                    detected=True,
                    anomaly_type="SENSITIVE_DATA_EXPOSURE",
                    severity="CRITICAL",
                    detail=f"Possível exposição de dados sensíveis",
                    score=0.9,
                    evidence=[entry.get('raw_line', '')[:200]],
                    extra={'pattern_matched': pattern.pattern}
                )
        
        return DetectionResult(detected=False)


class AnomalousTimePlugin(BaseDetectionPlugin):
    """Deteta atividade em horários anómalos."""
    
    name = "Anomalous Time Detector"
    version = "1.0"
    author = "Log Sentinel"
    description = "Deteta atividade fora de horário normal"
    
    default_config = {
        'normal_hours_start': 8,   # 8:00
        'normal_hours_end': 20,    # 20:00
        'weekend_suspicious': True,
    }
    
    def detect(self, entry: Dict) -> DetectionResult:
        timestamp = entry.get('timestamp')
        
        if not timestamp:
            return DetectionResult(detected=False)
        
        if isinstance(timestamp, str):
            try:
                timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            except:
                return DetectionResult(detected=False)
        
        hour = timestamp.hour
        weekday = timestamp.weekday()
        
        is_outside_hours = (hour < self.config['normal_hours_start'] or 
                          hour >= self.config['normal_hours_end'])
        is_weekend = weekday >= 5
        
        if is_outside_hours or (is_weekend and self.config['weekend_suspicious']):
            severity = "MEDIUM" if is_outside_hours else "LOW"
            detail = f"Atividade em horário anómalo: {timestamp.strftime('%H:%M %A')}"
            
            return DetectionResult(
                detected=True,
                anomaly_type="ANOMALOUS_TIME",
                severity=severity,
                detail=detail,
                score=0.4 if is_outside_hours else 0.2,
                extra={'hour': hour, 'weekday': weekday}
            )
        
        return DetectionResult(detected=False)


# Init do pacote
def create_plugin_template(filepath: str, name: str, description: str) -> None:
    """
    Cria template de plugin.
    
    Args:
        filepath: Caminho para guardar
        name: Nome do plugin
        description: Descrição
    """
    template = f'''"""
{name} - Custom Detection Plugin
Created: {datetime.now().strftime('%Y-%m-%d')}
"""

from src.plugins.plugin_system import BaseDetectionPlugin, DetectionResult


class {name.replace(' ', '')}Plugin(BaseDetectionPlugin):
    """
    {description}
    """
    
    name = "{name}"
    version = "1.0"
    author = "Custom"
    description = "{description}"
    
    default_config = {{
        # Adicionar configurações aqui
    }}
    
    def detect(self, entry):
        """
        Lógica de deteção.
        
        Args:
            entry: Dicionário com dados do log
                   - raw_line: Linha original
                   - message: Mensagem processada
                   - source_ip: IP de origem
                   - timestamp: Data/hora
                   - url: URL (se web log)
                   - user: Utilizador
                   - status: Status code
        
        Returns:
            DetectionResult
        """
        message = entry.get('message', '') or entry.get('raw_line', '')
        
        # TODO: Implementar lógica de deteção
        # Exemplo:
        # if 'suspicious_pattern' in message.lower():
        #     return DetectionResult(
        #         detected=True,
        #         anomaly_type="CUSTOM_DETECTION",
        #         severity="MEDIUM",
        #         detail="Padrão suspeito detetado",
        #         score=0.7
        #     )
        
        return DetectionResult(detected=False)
'''
    
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(template)


# Teste
if __name__ == "__main__":
    print("🔧 Teste do Plugin System")
    
    manager = PluginManager()
    
    # Listar plugins
    print("\n📦 Plugins disponíveis:")
    for info in manager.get_plugins():
        print(f"  - {info.name} v{info.version} [{info.id}]")
    
    # Testar deteção
    test_entry = {
        'raw_line': 'GET /api/v1/users?password=secret123 HTTP/1.1',
        'source_ip': '192.168.1.100',
        'url': '/api/v1/users?password=secret123',
        'timestamp': datetime.now().replace(hour=3),  # 3:00 AM
    }
    
    results = manager.process_entry(test_entry)
    print(f"\n🔍 Deteções: {len(results)}")
    for r in results:
        print(f"  - {r.anomaly_type} [{r.severity}]: {r.detail}")
    
    print("\n✅ Teste concluído!")
