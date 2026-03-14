"""
Log Sentinel v2.0 - Machine Learning Module
============================================
Sistema de ML para deteção de anomalias.

Author: Duarte Cunha (Nº 2024271)
ISTEC - Instituto Superior de Tecnologias Avançadas de Lisboa
Ano Letivo: 2025/2026
"""

import numpy as np
from typing import List, Dict, Optional, Tuple, Any
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
import json

try:
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.preprocessing import StandardScaler, LabelEncoder
    from sklearn.model_selection import train_test_split
    import joblib
    SKLEARN_AVAILABLE = True
    print("[ML] scikit-learn importado com sucesso")
except ImportError as e:
    SKLEARN_AVAILABLE = False
    print(f"[ML] ERRO: scikit-learn não disponível: {e}")
    print("[ML] Instale com: pip install scikit-learn")


@dataclass
class MLPrediction:
    """Resultado de uma predição ML."""
    is_anomaly: bool
    anomaly_score: float
    confidence: float
    predicted_type: Optional[str] = None
    feature_importance: Optional[Dict[str, float]] = None


class FeatureExtractor:
    """Extrator de features para logs."""
    
    FEATURE_NAMES = [
        'hour_of_day', 'day_of_week', 'request_length', 'url_length',
        'num_special_chars', 'num_dots', 'num_slashes', 'num_params',
        'has_sql_keywords', 'has_script_tags', 'has_path_traversal',
        'has_encoded_chars', 'status_code_class', 'is_error_status',
        'response_size', 'ip_octet_1', 'ip_octet_4', 'is_private_ip',
        'user_agent_length', 'is_known_scanner',
    ]
    
    SQL_KEYWORDS = ['select', 'union', 'insert', 'update', 'delete', 'drop', 'exec']
    KNOWN_SCANNERS = ['nikto', 'nmap', 'sqlmap', 'dirbuster', 'gobuster', 'wpscan']
    
    def extract(self, entry: Dict) -> List[float]:
        """Extrai features de uma entrada de log."""
        features = []
        
        # Timestamp
        timestamp = entry.get('timestamp')
        if timestamp:
            if isinstance(timestamp, str):
                try:
                    timestamp = datetime.fromisoformat(timestamp)
                except:
                    timestamp = datetime.now()
            features.extend([timestamp.hour, timestamp.weekday()])
        else:
            features.extend([12, 3])
        
        # Message/URL
        message = str(entry.get('message', '') or entry.get('raw_line', ''))
        url = str(entry.get('url', '') or entry.get('target', '') or '')
        
        features.append(len(message))
        features.append(len(url))
        
        special_chars = sum(1 for c in message if not c.isalnum() and c not in ' \t\n')
        features.append(special_chars)
        features.append(message.count('.'))
        features.append(message.count('/') + message.count('\\'))
        features.append(url.count('&') + url.count('?'))
        
        msg_lower = message.lower()
        features.append(1 if any(kw in msg_lower for kw in self.SQL_KEYWORDS) else 0)
        features.append(1 if '<script' in msg_lower else 0)
        features.append(1 if '../' in message else 0)
        features.append(1 if '%' in message else 0)
        
        # Status
        status = entry.get('status', '') or entry.get('status_code', '')
        try:
            status_code = int(status) if status else 200
            features.append(status_code // 100)
            features.append(1 if status_code >= 400 else 0)
        except:
            features.extend([2, 0])
        
        # Size
        size = entry.get('size', 0)
        try:
            features.append(int(size) if size and size != '-' else 0)
        except:
            features.append(0)
        
        # IP
        ip = entry.get('source_ip', '') or entry.get('ip', '')
        if ip and '.' in ip:
            octets = ip.split('.')
            try:
                features.append(int(octets[0]))
                features.append(int(octets[3]) if len(octets) > 3 else 0)
                first = int(octets[0])
                is_private = first in [10, 127] or (first == 192 and octets[1] == '168')
                features.append(1 if is_private else 0)
            except:
                features.extend([0, 0, 0])
        else:
            features.extend([0, 0, 0])
        
        # User-Agent
        user_agent = str(entry.get('user_agent', '') or '')
        features.append(len(user_agent))
        features.append(1 if any(s in user_agent.lower() for s in self.KNOWN_SCANNERS) else 0)
        
        return features
    
    def extract_batch(self, entries: List[Dict]) -> np.ndarray:
        """Extrai features de múltiplas entradas."""
        return np.array([self.extract(e) for e in entries])


class AnomalyDetector:
    """Detetor de anomalias com Isolation Forest."""
    
    def __init__(self, models_dir: str = "data/models"):
        self.models_dir = Path(models_dir)
        self.models_dir.mkdir(parents=True, exist_ok=True)
        
        self.feature_extractor = FeatureExtractor()
        self.scaler = None
        self.isolation_forest = None
        self.classifier = None
        self.label_encoder = None
        self.is_trained = False
        self.training_samples = 0
        
        self._load_models()
    
    def _load_models(self) -> bool:
        """Carrega modelos guardados."""
        if not SKLEARN_AVAILABLE:
            return False
        try:
            scaler_path = self.models_dir / "scaler.pkl"
            iso_path = self.models_dir / "isolation_forest.pkl"
            
            if scaler_path.exists() and iso_path.exists():
                self.scaler = joblib.load(scaler_path)
                self.isolation_forest = joblib.load(iso_path)
                self.is_trained = True
                
                clf_path = self.models_dir / "classifier.pkl"
                le_path = self.models_dir / "label_encoder.pkl"
                if clf_path.exists():
                    self.classifier = joblib.load(clf_path)
                if le_path.exists():
                    self.label_encoder = joblib.load(le_path)
                return True
        except Exception as e:
            print(f"Erro ao carregar modelos: {e}")
        return False
    
    def _save_models(self) -> None:
        """Guarda modelos."""
        if not SKLEARN_AVAILABLE:
            return
        try:
            if self.scaler:
                joblib.dump(self.scaler, self.models_dir / "scaler.pkl")
            if self.isolation_forest:
                joblib.dump(self.isolation_forest, self.models_dir / "isolation_forest.pkl")
            if self.classifier:
                joblib.dump(self.classifier, self.models_dir / "classifier.pkl")
            if self.label_encoder:
                joblib.dump(self.label_encoder, self.models_dir / "label_encoder.pkl")
        except Exception as e:
            print(f"Erro ao guardar modelos: {e}")
    
    def train_anomaly_detector(self, entries: List[Dict], contamination: float = 0.1) -> Dict:
        """Treina Isolation Forest."""
        print(f"[AnomalyDetector] Iniciando treino com {len(entries)} entradas")
        
        if not SKLEARN_AVAILABLE:
            print("[AnomalyDetector] scikit-learn não disponível!")
            return {'error': 'scikit-learn não disponível', 'success': False}
        
        if len(entries) < 20:
            print(f"[AnomalyDetector] Poucas amostras: {len(entries)} < 20")
            return {'error': f'Mínimo 20 amostras (tem {len(entries)})', 'success': False}
        
        try:
            print("[AnomalyDetector] Extraindo features...")
            X = self.feature_extractor.extract_batch(entries)
            print(f"[AnomalyDetector] Features extraídas: shape={X.shape}")
            
            self.scaler = StandardScaler()
            X_scaled = self.scaler.fit_transform(X)
            print("[AnomalyDetector] Features normalizadas")
        
            self.isolation_forest = IsolationForest(
                n_estimators=100, contamination=contamination, random_state=42, n_jobs=-1
            )
            print("[AnomalyDetector] A treinar Isolation Forest...")
            self.isolation_forest.fit(X_scaled)
            
            scores = self.isolation_forest.decision_function(X_scaled)
            predictions = self.isolation_forest.predict(X_scaled)
            
            self.is_trained = True
            self.training_samples = len(entries)
            print(f"[AnomalyDetector] Treino concluído! is_trained={self.is_trained}")
            
            self._save_models()
            
            return {
                'success': True,
                'samples_trained': len(entries),
                'anomalies_found': int((predictions == -1).sum()),
                'mean_score': float(np.mean(scores)),
            }
        except Exception as e:
            print(f"[AnomalyDetector] ERRO: {e}")
            import traceback
            traceback.print_exc()
            return {'error': str(e), 'success': False}
    
    def train_classifier(self, entries: List[Dict], labels: List[str]) -> Dict:
        """Treina classificador de tipos."""
        if not SKLEARN_AVAILABLE:
            return {'error': 'scikit-learn não disponível'}
        if len(entries) < 50:
            return {'error': 'Mínimo 50 amostras'}
        
        X = self.feature_extractor.extract_batch(entries)
        if self.scaler is None:
            self.scaler = StandardScaler()
            X_scaled = self.scaler.fit_transform(X)
        else:
            X_scaled = self.scaler.transform(X)
        
        self.label_encoder = LabelEncoder()
        y = self.label_encoder.fit_transform(labels)
        
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=0.2, random_state=42
        )
        
        self.classifier = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
        self.classifier.fit(X_train, y_train)
        
        accuracy = (self.classifier.predict(X_test) == y_test).mean()
        self._save_models()
        
        return {
            'samples_trained': len(entries),
            'accuracy': float(accuracy),
            'classes': list(self.label_encoder.classes_)
        }
    
    def predict(self, entry: Dict) -> MLPrediction:
        """Faz predição para uma entrada."""
        if not self.is_trained or not SKLEARN_AVAILABLE:
            return MLPrediction(is_anomaly=False, anomaly_score=0.0, confidence=0.0)
        
        features = self.feature_extractor.extract(entry)
        X = np.array([features])
        X_scaled = self.scaler.transform(X)
        
        anomaly_score = float(self.isolation_forest.decision_function(X_scaled)[0])
        is_anomaly = self.isolation_forest.predict(X_scaled)[0] == -1
        confidence = max(0, min(1, (0.5 - anomaly_score)))
        
        predicted_type = None
        if self.classifier is not None and is_anomaly:
            pred_class = self.classifier.predict(X_scaled)[0]
            predicted_type = self.label_encoder.inverse_transform([pred_class])[0]
        
        return MLPrediction(
            is_anomaly=is_anomaly,
            anomaly_score=anomaly_score,
            confidence=confidence,
            predicted_type=predicted_type
        )
    
    def predict_batch(self, entries: List[Dict]) -> List[MLPrediction]:
        """Predições em lote."""
        return [self.predict(e) for e in entries]
    
    def get_model_info(self) -> Dict:
        """Informações do modelo."""
        return {
            'sklearn_available': SKLEARN_AVAILABLE,
            'is_trained': self.is_trained,
            'training_samples': self.training_samples,
            'has_classifier': self.classifier is not None,
        }


if __name__ == "__main__":
    print("🔧 Teste ML Module")
    detector = AnomalyDetector("test_models")
    print(f"Info: {detector.get_model_info()}")
    
    import shutil
    shutil.rmtree("test_models", ignore_errors=True)
    print("✅ Teste concluído!")
