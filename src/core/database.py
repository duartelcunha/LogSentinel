"""
Log Sentinel v2.0 - Database Manager
=====================================
Gestão da base de dados SQLite com suporte avançado.

Author: Duarte Cunha (Nº 2024271)
ISTEC - Instituto Superior de Tecnologias Avançadas de Lisboa
Ano Letivo: 2025/2026
"""

import sqlite3
import os
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple, Any
from contextlib import contextmanager
from pathlib import Path
import json


class DatabaseManager:
    """
    Gestor de base de dados SQLite para o Log Sentinel.
    
    Funcionalidades:
    - Armazenamento de anomalias detetadas
    - Gestão de sessões de análise
    - Timeline de eventos
    - Estatísticas e métricas
    - Correlação de eventos
    - Suporte a plugins
    """
    
    def __init__(self, db_path: str = "data/sentinel.db"):
        """
        Inicializa o gestor de base de dados.
        
        Args:
            db_path: Caminho para o ficheiro da base de dados
        """
        self.db_path = Path(db_path)
        self._ensure_directory()
        self._init_database()
    
    def _ensure_directory(self) -> None:
        """Garante que o diretório da base de dados existe."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
    
    @contextmanager
    def _get_connection(self):
        """Context manager para conexões."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()
    
    def _init_database(self) -> None:
        """Inicializa o schema da base de dados."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # === Tabela de Anomalias ===
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS anomalies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    type TEXT NOT NULL,
                    severity TEXT NOT NULL DEFAULT 'MEDIUM',
                    source_ip TEXT,
                    target TEXT,
                    detail TEXT NOT NULL,
                    log_line TEXT,
                    log_file TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    session_id TEXT,
                    score REAL DEFAULT 0.0,
                    ml_score REAL DEFAULT NULL,
                    is_correlated INTEGER DEFAULT 0,
                    correlation_group TEXT,
                    reviewed INTEGER DEFAULT 0,
                    notes TEXT
                )
            ''')
            
            # === Tabela de Sessões ===
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    start_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                    end_time DATETIME,
                    files_analyzed INTEGER DEFAULT 0,
                    total_lines INTEGER DEFAULT 0,
                    anomalies_found INTEGER DEFAULT 0,
                    status TEXT DEFAULT 'RUNNING',
                    notes TEXT
                )
            ''')
            
            # === Tabela de Estatísticas por IP ===
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ip_stats (
                    ip TEXT PRIMARY KEY,
                    first_seen DATETIME,
                    last_seen DATETIME,
                    total_requests INTEGER DEFAULT 0,
                    failed_attempts INTEGER DEFAULT 0,
                    anomaly_count INTEGER DEFAULT 0,
                    risk_score REAL DEFAULT 0.0,
                    country TEXT,
                    is_blocked INTEGER DEFAULT 0
                )
            ''')
            
            # === Tabela de Timeline ===
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS timeline (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_time DATETIME NOT NULL,
                    event_type TEXT NOT NULL,
                    severity TEXT,
                    source_ip TEXT,
                    description TEXT,
                    anomaly_id INTEGER,
                    session_id TEXT,
                    FOREIGN KEY (anomaly_id) REFERENCES anomalies(id)
                )
            ''')
            
            # === Tabela de Correlações ===
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS correlations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    group_id TEXT NOT NULL,
                    anomaly_ids TEXT NOT NULL,
                    correlation_type TEXT,
                    confidence REAL DEFAULT 0.0,
                    description TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # === Tabela de Alertas ===
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    anomaly_id INTEGER,
                    alert_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    message TEXT,
                    is_read INTEGER DEFAULT 0,
                    is_dismissed INTEGER DEFAULT 0,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (anomaly_id) REFERENCES anomalies(id)
                )
            ''')
            
            # === Tabela de Plugins ===
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS plugins (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    version TEXT,
                    description TEXT,
                    enabled INTEGER DEFAULT 1,
                    config TEXT,
                    installed_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # === Tabela de ML Training Data ===
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ml_training_data (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    features TEXT NOT NULL,
                    label INTEGER NOT NULL,
                    anomaly_type TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # === Índices ===
            indexes = [
                'CREATE INDEX IF NOT EXISTS idx_anomalies_type ON anomalies(type)',
                'CREATE INDEX IF NOT EXISTS idx_anomalies_severity ON anomalies(severity)',
                'CREATE INDEX IF NOT EXISTS idx_anomalies_timestamp ON anomalies(timestamp)',
                'CREATE INDEX IF NOT EXISTS idx_anomalies_source_ip ON anomalies(source_ip)',
                'CREATE INDEX IF NOT EXISTS idx_anomalies_session ON anomalies(session_id)',
                'CREATE INDEX IF NOT EXISTS idx_timeline_time ON timeline(event_time)',
                'CREATE INDEX IF NOT EXISTS idx_alerts_read ON alerts(is_read)',
            ]
            for idx in indexes:
                cursor.execute(idx)
    
    # === CRUD Operations ===
    
    def insert_anomaly(self, anomaly_type: str, detail: str, severity: str = "MEDIUM",
                       source_ip: str = None, target: str = None, log_line: str = None,
                       log_file: str = None, session_id: str = None, score: float = 0.0,
                       ml_score: float = None) -> int:
        """Insere uma nova anomalia."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO anomalies 
                (type, severity, source_ip, target, detail, log_line, log_file, 
                 session_id, score, ml_score)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (anomaly_type, severity, source_ip, target, detail, log_line, 
                  log_file, session_id, score, ml_score))
            
            anomaly_id = cursor.lastrowid
            
            # Criar entrada na timeline
            cursor.execute('''
                INSERT INTO timeline (event_time, event_type, severity, source_ip, 
                                      description, anomaly_id, session_id)
                VALUES (datetime('now'), ?, ?, ?, ?, ?, ?)
            ''', (anomaly_type, severity, source_ip, detail[:200], anomaly_id, session_id))
            
            # Atualizar estatísticas do IP
            if source_ip:
                self._update_ip_stats(cursor, source_ip, anomaly_type, severity)
            
            return anomaly_id
    
    def _update_ip_stats(self, cursor, ip: str, anomaly_type: str, severity: str) -> None:
        """Atualiza estatísticas do IP."""
        cursor.execute('SELECT * FROM ip_stats WHERE ip = ?', (ip,))
        existing = cursor.fetchone()
        
        if existing:
            risk_delta = {'CRITICAL': 0.3, 'HIGH': 0.2, 'MEDIUM': 0.1, 'LOW': 0.05}.get(severity, 0.05)
            cursor.execute('''
                UPDATE ip_stats SET 
                    last_seen = datetime('now'),
                    anomaly_count = anomaly_count + 1,
                    risk_score = MIN(1.0, risk_score + ?)
                WHERE ip = ?
            ''', (risk_delta, ip))
        else:
            cursor.execute('''
                INSERT INTO ip_stats (ip, first_seen, last_seen, anomaly_count, risk_score)
                VALUES (?, datetime('now'), datetime('now'), 1, 0.2)
            ''', (ip,))
    
    def save_session(self, log_file: str, session_id: str = None) -> str:
        """
        Guarda uma sessão de análise.
        
        Args:
            log_file: Caminho do ficheiro analisado
            session_id: ID opcional (gerado se não fornecido)
            
        Returns:
            session_id
        """
        if not session_id:
            session_id = f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Criar tabela sessions se não existir
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    log_file TEXT,
                    started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    ended_at DATETIME,
                    total_lines INTEGER DEFAULT 0,
                    anomalies_found INTEGER DEFAULT 0,
                    status TEXT DEFAULT 'running'
                )
            ''')
            
            cursor.execute('''
                INSERT OR REPLACE INTO sessions (id, log_file, started_at, status)
                VALUES (?, ?, datetime('now'), 'running')
            ''', (session_id, log_file))
            
        return session_id
    
    def end_session(self, session_id: str, total_lines: int = 0, anomalies_found: int = 0):
        """Finaliza uma sessão de análise."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE sessions SET 
                    ended_at = datetime('now'),
                    total_lines = ?,
                    anomalies_found = ?,
                    status = 'completed'
                WHERE id = ?
            ''', (total_lines, anomalies_found, session_id))
    
    def get_anomalies(self, limit: int = 100, offset: int = 0,
                      anomaly_type: str = None, severity: str = None,
                      session_id: str = None, source_ip: str = None,
                      start_date: str = None, end_date: str = None) -> List[Dict]:
        """Obtém lista de anomalias com filtros."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            query = "SELECT * FROM anomalies WHERE 1=1"
            params = []
            
            if anomaly_type:
                query += " AND type = ?"
                params.append(anomaly_type)
            
            if severity:
                query += " AND severity = ?"
                params.append(severity)
            
            if session_id:
                query += " AND session_id = ?"
                params.append(session_id)
            
            if source_ip:
                query += " AND source_ip = ?"
                params.append(source_ip)
            
            if start_date:
                query += " AND timestamp >= ?"
                params.append(start_date)
            
            if end_date:
                query += " AND timestamp <= ?"
                params.append(end_date)
            
            query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])
            
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
    
    def get_statistics(self) -> Dict:
        """Obtém estatísticas gerais."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            stats = {
                'total_anomalies': 0,
                'by_type': {},
                'by_severity': {},
                'top_ips': [],
                'recent_count': 0,
                'today_count': 0,
                'week_count': 0,
                'critical_count': 0,
                'unreviewed_count': 0
            }
            
            # Total
            cursor.execute("SELECT COUNT(*) FROM anomalies")
            stats['total_anomalies'] = cursor.fetchone()[0]
            
            # Por tipo
            cursor.execute("""
                SELECT type, COUNT(*) as count 
                FROM anomalies GROUP BY type ORDER BY count DESC
            """)
            stats['by_type'] = {row['type']: row['count'] for row in cursor.fetchall()}
            
            # Por severidade
            cursor.execute("""
                SELECT severity, COUNT(*) as count 
                FROM anomalies GROUP BY severity
            """)
            stats['by_severity'] = {row['severity']: row['count'] for row in cursor.fetchall()}
            
            # Top IPs
            cursor.execute("""
                SELECT source_ip, COUNT(*) as count 
                FROM anomalies WHERE source_ip IS NOT NULL 
                GROUP BY source_ip ORDER BY count DESC LIMIT 10
            """)
            stats['top_ips'] = [(row['source_ip'], row['count']) for row in cursor.fetchall()]
            
            # Recentes (24h)
            cursor.execute("""
                SELECT COUNT(*) FROM anomalies 
                WHERE timestamp >= datetime('now', '-24 hours')
            """)
            stats['recent_count'] = cursor.fetchone()[0]
            
            # Hoje
            cursor.execute("""
                SELECT COUNT(*) FROM anomalies 
                WHERE date(timestamp) = date('now')
            """)
            stats['today_count'] = cursor.fetchone()[0]
            
            # Esta semana
            cursor.execute("""
                SELECT COUNT(*) FROM anomalies 
                WHERE timestamp >= datetime('now', '-7 days')
            """)
            stats['week_count'] = cursor.fetchone()[0]
            
            # Críticos
            cursor.execute("SELECT COUNT(*) FROM anomalies WHERE severity = 'CRITICAL'")
            stats['critical_count'] = cursor.fetchone()[0]
            
            # Não revistos
            cursor.execute("SELECT COUNT(*) FROM anomalies WHERE reviewed = 0")
            stats['unreviewed_count'] = cursor.fetchone()[0]
            
            return stats
    
    def get_timeline_data(self, hours: int = 24, interval: str = 'hour') -> List[Dict]:
        """Obtém dados para timeline."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            if interval == 'hour':
                fmt = '%Y-%m-%d %H:00'
            elif interval == 'day':
                fmt = '%Y-%m-%d'
            else:
                fmt = '%Y-%m-%d %H:%M'
            
            cursor.execute(f"""
                SELECT strftime('{fmt}', timestamp) as time_bucket,
                       COUNT(*) as total,
                       SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical,
                       SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) as high,
                       SUM(CASE WHEN severity = 'MEDIUM' THEN 1 ELSE 0 END) as medium,
                       SUM(CASE WHEN severity = 'LOW' THEN 1 ELSE 0 END) as low
                FROM anomalies
                WHERE timestamp >= datetime('now', '-{hours} hours')
                GROUP BY time_bucket
                ORDER BY time_bucket
            """)
            
            return [dict(row) for row in cursor.fetchall()]
    
    def get_real_time_metrics(self) -> Dict:
        """Obtém métricas em tempo real para o dashboard."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            metrics = {}
            
            # Últimos 5 minutos
            cursor.execute("""
                SELECT COUNT(*) FROM anomalies 
                WHERE timestamp >= datetime('now', '-5 minutes')
            """)
            metrics['last_5min'] = cursor.fetchone()[0]
            
            # Última hora
            cursor.execute("""
                SELECT COUNT(*) FROM anomalies 
                WHERE timestamp >= datetime('now', '-1 hour')
            """)
            metrics['last_hour'] = cursor.fetchone()[0]
            
            # Taxa por minuto (última hora)
            metrics['rate_per_min'] = round(metrics['last_hour'] / 60, 2)
            
            # Severidade dominante (última hora)
            cursor.execute("""
                SELECT severity, COUNT(*) as c FROM anomalies 
                WHERE timestamp >= datetime('now', '-1 hour')
                GROUP BY severity ORDER BY c DESC LIMIT 1
            """)
            row = cursor.fetchone()
            metrics['dominant_severity'] = row['severity'] if row else 'N/A'
            
            # IPs ativos (última hora)
            cursor.execute("""
                SELECT COUNT(DISTINCT source_ip) FROM anomalies 
                WHERE timestamp >= datetime('now', '-1 hour') AND source_ip IS NOT NULL
            """)
            metrics['active_ips'] = cursor.fetchone()[0]
            
            return metrics
    
    # === Alerts ===
    
    def create_alert(self, anomaly_id: int, alert_type: str, severity: str,
                     title: str, message: str = None) -> int:
        """Cria um novo alerta."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO alerts (anomaly_id, alert_type, severity, title, message)
                VALUES (?, ?, ?, ?, ?)
            ''', (anomaly_id, alert_type, severity, title, message))
            return cursor.lastrowid
    
    def get_unread_alerts(self, limit: int = 50) -> List[Dict]:
        """Obtém alertas não lidos."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT a.*, an.type as anomaly_type, an.source_ip
                FROM alerts a
                LEFT JOIN anomalies an ON a.anomaly_id = an.id
                WHERE a.is_read = 0 AND a.is_dismissed = 0
                ORDER BY a.created_at DESC
                LIMIT ?
            ''', (limit,))
            return [dict(row) for row in cursor.fetchall()]
    
    def mark_alert_read(self, alert_id: int) -> None:
        """Marca alerta como lido."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE alerts SET is_read = 1 WHERE id = ?', (alert_id,))
    
    def dismiss_alert(self, alert_id: int) -> None:
        """Descarta alerta."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE alerts SET is_dismissed = 1 WHERE id = ?', (alert_id,))
    
    # === Correlations ===
    
    def add_correlation(self, anomaly_ids: List[int], correlation_type: str,
                        confidence: float, description: str) -> str:
        """Adiciona correlação entre anomalias."""
        import uuid
        group_id = str(uuid.uuid4())[:8]
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO correlations (group_id, anomaly_ids, correlation_type, 
                                         confidence, description)
                VALUES (?, ?, ?, ?, ?)
            ''', (group_id, json.dumps(anomaly_ids), correlation_type, confidence, description))
            
            # Marcar anomalias como correlacionadas
            cursor.execute(f'''
                UPDATE anomalies SET is_correlated = 1, correlation_group = ?
                WHERE id IN ({','.join('?' * len(anomaly_ids))})
            ''', [group_id] + anomaly_ids)
            
            return group_id
    
    def get_correlations(self) -> List[Dict]:
        """Obtém todas as correlações."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM correlations ORDER BY created_at DESC')
            correlations = [dict(row) for row in cursor.fetchall()]
            
            for c in correlations:
                c['anomaly_ids'] = json.loads(c['anomaly_ids'])
            
            return correlations
    
    # === Sessions ===
    
    def create_session(self, session_id: str) -> None:
        """Cria uma nova sessão."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT OR REPLACE INTO sessions (id, start_time, status) VALUES (?, ?, 'RUNNING')",
                (session_id, datetime.now().isoformat())
            )
    
    def update_session(self, session_id: str, files: int = 0, lines: int = 0, 
                       anomalies: int = 0, status: str = 'COMPLETED') -> None:
        """Atualiza sessão."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE sessions SET 
                    files_analyzed = ?, total_lines = ?, anomalies_found = ?,
                    end_time = ?, status = ?
                WHERE id = ?
            """, (files, lines, anomalies, datetime.now().isoformat(), status, session_id))
    
    def get_sessions(self, limit: int = 20) -> List[Dict]:
        """Obtém histórico de sessões."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM sessions ORDER BY start_time DESC LIMIT ?
            ''', (limit,))
            return [dict(row) for row in cursor.fetchall()]
    
    # === ML Data ===
    
    def save_ml_training_data(self, features: List[float], label: int, 
                              anomaly_type: str = None) -> None:
        """Guarda dados de treino ML."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO ml_training_data (features, label, anomaly_type)
                VALUES (?, ?, ?)
            ''', (json.dumps(features), label, anomaly_type))
    
    def get_ml_training_data(self, limit: int = 10000) -> List[Dict]:
        """Obtém dados de treino ML."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT features, label, anomaly_type FROM ml_training_data
                ORDER BY created_at DESC LIMIT ?
            ''', (limit,))
            data = []
            for row in cursor.fetchall():
                data.append({
                    'features': json.loads(row['features']),
                    'label': row['label'],
                    'anomaly_type': row['anomaly_type']
                })
            return data
    
    # === Cleanup ===
    
    def clear_anomalies(self, session_id: str = None) -> int:
        """Remove anomalias."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            if session_id:
                cursor.execute("DELETE FROM anomalies WHERE session_id = ?", (session_id,))
            else:
                cursor.execute("DELETE FROM anomalies")
                cursor.execute("DELETE FROM timeline")
                cursor.execute("DELETE FROM alerts")
                cursor.execute("DELETE FROM correlations")
            
            return cursor.rowcount
    
    def vacuum(self) -> None:
        """Otimiza a base de dados."""
        with self._get_connection() as conn:
            conn.execute("VACUUM")


# Teste do módulo
if __name__ == "__main__":
    print("🔧 Teste do DatabaseManager v2")
    print("-" * 40)
    
    db = DatabaseManager("test_sentinel_v2.db")
    
    # Inserir anomalia de teste
    anomaly_id = db.insert_anomaly(
        anomaly_type="BRUTE_FORCE",
        detail="5 tentativas falhadas de login",
        severity="HIGH",
        source_ip="192.168.1.100",
        target="admin",
        score=0.85
    )
    print(f"✅ Anomalia inserida: ID {anomaly_id}")
    
    # Criar alerta
    alert_id = db.create_alert(
        anomaly_id=anomaly_id,
        alert_type="THREAT_DETECTED",
        severity="HIGH",
        title="Brute Force Detectado",
        message="Múltiplas tentativas falhadas de IP suspeito"
    )
    print(f"✅ Alerta criado: ID {alert_id}")
    
    # Estatísticas
    stats = db.get_statistics()
    print(f"📊 Total anomalias: {stats['total_anomalies']}")
    
    # Métricas tempo real
    metrics = db.get_real_time_metrics()
    print(f"📈 Última hora: {metrics['last_hour']} eventos")
    
    # Limpar
    import os
    os.remove("test_sentinel_v2.db")
    print("✅ Teste concluído!")
