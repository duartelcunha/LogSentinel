"""
Log Sentinel v2.0 - Real-Time Monitor
======================================
Monitorização em tempo real de ficheiros de log.

Author: Duarte Cunha (Nº 2024271)
ISTEC - Instituto Superior de Tecnologias Avançadas de Lisboa
Ano Letivo: 2025/2026
"""

import os
import time
import threading
from pathlib import Path
from typing import Callable, Optional, List, Dict
from datetime import datetime
from dataclasses import dataclass
from queue import Queue
import json

# Watchdog para monitorização de ficheiros
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileModifiedEvent
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    print("[Monitor] watchdog não disponível. Instale com: pip install watchdog")


@dataclass
class LogEvent:
    """Evento de log em tempo real."""
    timestamp: datetime
    filepath: str
    line: str
    line_number: int
    is_new: bool = True


class LogFileHandler(FileSystemEventHandler):
    """Handler para eventos de ficheiros de log."""
    
    def __init__(self, callback: Callable[[LogEvent], None], 
                 file_positions: Dict[str, int] = None):
        super().__init__()
        self.callback = callback
        self.file_positions = file_positions or {}
        self._lock = threading.Lock()
    
    def on_modified(self, event):
        """Chamado quando um ficheiro é modificado."""
        if event.is_directory:
            return
        
        filepath = event.src_path
        
        # Verificar se é ficheiro de log
        if not self._is_log_file(filepath):
            return
        
        # Processar novas linhas
        self._process_new_lines(filepath)
    
    def _is_log_file(self, filepath: str) -> bool:
        """Verifica se é um ficheiro de log."""
        extensions = ['.log', '.txt', '.json']
        return any(filepath.lower().endswith(ext) for ext in extensions)
    
    def _process_new_lines(self, filepath: str):
        """Processa novas linhas adicionadas ao ficheiro."""
        with self._lock:
            try:
                # Obter posição anterior
                last_pos = self.file_positions.get(filepath, 0)
                
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    # Ir para a última posição conhecida
                    f.seek(last_pos)
                    
                    # Ler novas linhas
                    line_number = sum(1 for _ in open(filepath, 'r', encoding='utf-8', errors='ignore'))
                    
                    for line in f:
                        line = line.strip()
                        if line:
                            event = LogEvent(
                                timestamp=datetime.now(),
                                filepath=filepath,
                                line=line,
                                line_number=line_number,
                                is_new=True
                            )
                            self.callback(event)
                            line_number += 1
                    
                    # Atualizar posição
                    self.file_positions[filepath] = f.tell()
                    
            except Exception as e:
                print(f"[Monitor] Erro ao processar {filepath}: {e}")


class RealTimeMonitor:
    """Monitor de logs em tempo real."""
    
    def __init__(self):
        self.observer: Optional[Observer] = None
        self.is_running = False
        self.watched_paths: List[str] = []
        self.file_positions: Dict[str, int] = {}
        self.event_queue: Queue = Queue()
        self.callbacks: List[Callable[[LogEvent], None]] = []
        
        # Estatísticas
        self.stats = {
            'events_processed': 0,
            'files_monitored': 0,
            'start_time': None,
            'last_event': None
        }
    
    def add_callback(self, callback: Callable[[LogEvent], None]):
        """Adiciona callback para eventos."""
        self.callbacks.append(callback)
    
    def _dispatch_event(self, event: LogEvent):
        """Despacha evento para todos os callbacks."""
        self.stats['events_processed'] += 1
        self.stats['last_event'] = datetime.now()
        
        for callback in self.callbacks:
            try:
                callback(event)
            except Exception as e:
                print(f"[Monitor] Erro em callback: {e}")
    
    def start(self, paths: List[str]) -> bool:
        """Inicia monitorização."""
        if not WATCHDOG_AVAILABLE:
            print("[Monitor] watchdog não disponível")
            return False
        
        if self.is_running:
            print("[Monitor] Já está em execução")
            return False
        
        self.watched_paths = []
        self.observer = Observer()
        
        handler = LogFileHandler(
            callback=self._dispatch_event,
            file_positions=self.file_positions
        )
        
        for path in paths:
            path_obj = Path(path)
            
            if path_obj.is_file():
                # Monitorizar diretório do ficheiro
                watch_dir = str(path_obj.parent)
                self.watched_paths.append(path)
                # Inicializar posição no fim do ficheiro
                self.file_positions[path] = os.path.getsize(path)
            elif path_obj.is_dir():
                watch_dir = path
                self.watched_paths.append(path)
            else:
                print(f"[Monitor] Caminho inválido: {path}")
                continue
            
            self.observer.schedule(handler, watch_dir, recursive=False)
            print(f"[Monitor] A monitorizar: {watch_dir}")
        
        self.observer.start()
        self.is_running = True
        self.stats['start_time'] = datetime.now()
        self.stats['files_monitored'] = len(self.watched_paths)
        
        print(f"[Monitor] Iniciado - {len(self.watched_paths)} caminhos monitorizados")
        return True
    
    def stop(self):
        """Para monitorização."""
        if self.observer and self.is_running:
            self.observer.stop()
            self.observer.join(timeout=5)
            self.is_running = False
            print("[Monitor] Parado")
    
    def get_stats(self) -> Dict:
        """Retorna estatísticas."""
        uptime = None
        if self.stats['start_time']:
            uptime = (datetime.now() - self.stats['start_time']).total_seconds()
        
        return {
            **self.stats,
            'is_running': self.is_running,
            'uptime_seconds': uptime,
            'watched_paths': self.watched_paths
        }


class TailFollower:
    """Segue ficheiro como 'tail -f' (alternativa sem watchdog)."""
    
    def __init__(self, filepath: str, callback: Callable[[str], None]):
        self.filepath = filepath
        self.callback = callback
        self.running = False
        self._thread: Optional[threading.Thread] = None
    
    def start(self):
        """Inicia seguimento."""
        self.running = True
        self._thread = threading.Thread(target=self._follow, daemon=True)
        self._thread.start()
    
    def stop(self):
        """Para seguimento."""
        self.running = False
        if self._thread:
            self._thread.join(timeout=2)
    
    def _follow(self):
        """Segue o ficheiro."""
        try:
            with open(self.filepath, 'r', encoding='utf-8', errors='ignore') as f:
                # Ir para o fim
                f.seek(0, 2)
                
                while self.running:
                    line = f.readline()
                    if line:
                        self.callback(line.strip())
                    else:
                        time.sleep(0.1)
        except Exception as e:
            print(f"[TailFollower] Erro: {e}")


# Teste
if __name__ == "__main__":
    print("🔍 Teste do RealTimeMonitor")
    
    def on_event(event: LogEvent):
        print(f"[EVENTO] {event.filepath}: {event.line[:50]}...")
    
    monitor = RealTimeMonitor()
    monitor.add_callback(on_event)
    
    if monitor.start(["."]):
        print("Monitor iniciado. Ctrl+C para parar.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            monitor.stop()
    else:
        print("Falha ao iniciar monitor")
