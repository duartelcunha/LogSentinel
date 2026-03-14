"""
Log Sentinel v2.0 - Pre-trained ML Models
==========================================
Modelos de Machine Learning pré-treinados para diferentes cenários.

Author: Duarte Cunha (Nº 2024271)
ISTEC - Instituto Superior de Tecnologias Avançadas de Lisboa
Ano Letivo: 2025/2026
"""

import numpy as np
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import json

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    import joblib
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


class PretrainedModels:
    """Gestor de modelos pré-treinados."""
    
    # Perfis de treino para diferentes cenários
    PROFILES = {
        'web_server': {
            'name': 'Web Server (Apache/Nginx)',
            'description': 'Otimizado para logs de servidores web',
            'contamination': 0.1,
            'features_weight': {
                'request_length': 1.5,
                'num_special_chars': 2.0,
                'has_sql_keywords': 2.5,
                'has_script_tags': 2.5,
                'is_error_status': 1.5
            }
        },
        'auth_server': {
            'name': 'Authentication Server',
            'description': 'Otimizado para logs de autenticação',
            'contamination': 0.05,
            'features_weight': {
                'hour_of_day': 2.0,
                'num_special_chars': 1.5,
                'is_error_status': 2.5
            }
        },
        'api_gateway': {
            'name': 'API Gateway',
            'description': 'Otimizado para logs de APIs',
            'contamination': 0.08,
            'features_weight': {
                'request_length': 1.5,
                'num_params': 2.0,
                'response_size': 1.5
            }
        },
        'firewall': {
            'name': 'Firewall/IDS',
            'description': 'Otimizado para logs de firewall',
            'contamination': 0.15,
            'features_weight': {
                'ip_octet_1': 1.5,
                'ip_octet_4': 1.5,
                'is_private_ip': 2.0
            }
        },
        'database': {
            'name': 'Database Server',
            'description': 'Otimizado para logs de bases de dados',
            'contamination': 0.05,
            'features_weight': {
                'hour_of_day': 2.0,
                'has_sql_keywords': 1.0,  # Normal em DB
                'request_length': 2.0
            }
        },
        'general': {
            'name': 'General Purpose',
            'description': 'Modelo genérico para qualquer tipo de log',
            'contamination': 0.1,
            'features_weight': {}  # Pesos iguais
        }
    }
    
    # Dados sintéticos para pré-treino
    SYNTHETIC_DATA = {
        'web_server': [
            # Normal requests
            {'hour': 10, 'request_len': 50, 'special_chars': 2, 'sql_kw': 0, 'script': 0, 'error': 0},
            {'hour': 11, 'request_len': 80, 'special_chars': 3, 'sql_kw': 0, 'script': 0, 'error': 0},
            {'hour': 14, 'request_len': 45, 'special_chars': 1, 'sql_kw': 0, 'script': 0, 'error': 0},
            {'hour': 15, 'request_len': 100, 'special_chars': 5, 'sql_kw': 0, 'script': 0, 'error': 0},
            {'hour': 9, 'request_len': 60, 'special_chars': 2, 'sql_kw': 0, 'script': 0, 'error': 0},
            # Anomalies
            {'hour': 3, 'request_len': 500, 'special_chars': 50, 'sql_kw': 1, 'script': 0, 'error': 1},
            {'hour': 2, 'request_len': 300, 'special_chars': 30, 'sql_kw': 0, 'script': 1, 'error': 0},
            {'hour': 4, 'request_len': 1000, 'special_chars': 100, 'sql_kw': 1, 'script': 1, 'error': 1},
        ],
        'auth_server': [
            # Normal logins
            {'hour': 9, 'special_chars': 0, 'error': 0, 'attempts': 1},
            {'hour': 10, 'special_chars': 0, 'error': 0, 'attempts': 1},
            {'hour': 14, 'special_chars': 0, 'error': 0, 'attempts': 1},
            {'hour': 16, 'special_chars': 0, 'error': 1, 'attempts': 1},  # 1 erro é normal
            # Anomalies
            {'hour': 3, 'special_chars': 10, 'error': 1, 'attempts': 50},
            {'hour': 4, 'special_chars': 5, 'error': 1, 'attempts': 100},
        ]
    }
    
    def __init__(self, models_dir: str = "data/models"):
        self.models_dir = Path(models_dir)
        self.models_dir.mkdir(parents=True, exist_ok=True)
        self.loaded_models: Dict[str, Tuple] = {}  # (model, scaler)
    
    def get_available_profiles(self) -> List[Dict]:
        """Retorna perfis disponíveis."""
        return [
            {
                'id': profile_id,
                'name': profile['name'],
                'description': profile['description']
            }
            for profile_id, profile in self.PROFILES.items()
        ]
    
    def create_pretrained_model(self, profile_id: str) -> Optional[Tuple]:
        """Cria modelo pré-treinado para um perfil."""
        if not SKLEARN_AVAILABLE:
            print("[PretrainedModels] scikit-learn não disponível")
            return None
        
        if profile_id not in self.PROFILES:
            print(f"[PretrainedModels] Perfil desconhecido: {profile_id}")
            return None
        
        profile = self.PROFILES[profile_id]
        
        # Gerar dados sintéticos expandidos
        X = self._generate_training_data(profile_id, n_samples=500)
        
        # Normalizar
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        
        # Treinar modelo
        model = IsolationForest(
            n_estimators=100,
            contamination=profile['contamination'],
            random_state=42,
            n_jobs=-1
        )
        model.fit(X_scaled)
        
        print(f"[PretrainedModels] Modelo criado: {profile['name']}")
        return (model, scaler)
    
    def _generate_training_data(self, profile_id: str, n_samples: int = 500) -> np.ndarray:
        """Gera dados de treino sintéticos."""
        np.random.seed(42)
        
        # Features base (20 dimensões para compatibilidade)
        n_features = 20
        
        if profile_id == 'web_server':
            # Tráfego web normal
            normal_ratio = 0.9
            n_normal = int(n_samples * normal_ratio)
            n_anomaly = n_samples - n_normal
            
            # Normal: distribuição típica de tráfego web
            normal_data = np.zeros((n_normal, n_features))
            normal_data[:, 0] = np.random.choice(range(8, 20), n_normal)  # hora (8h-20h)
            normal_data[:, 1] = np.random.choice(range(0, 5), n_normal)   # dia semana
            normal_data[:, 2] = np.random.normal(100, 30, n_normal)       # request_length
            normal_data[:, 3] = np.random.normal(50, 20, n_normal)        # url_length
            normal_data[:, 4] = np.random.poisson(3, n_normal)            # special_chars
            normal_data[:, 5] = np.random.poisson(2, n_normal)            # dots
            normal_data[:, 6] = np.random.poisson(3, n_normal)            # slashes
            normal_data[:, 7] = np.random.poisson(1, n_normal)            # params
            normal_data[:, 8] = 0                                          # sql_keywords
            normal_data[:, 9] = 0                                          # script_tags
            normal_data[:, 10] = 0                                         # path_traversal
            normal_data[:, 11] = np.random.choice([0, 1], n_normal, p=[0.95, 0.05])  # encoded
            normal_data[:, 12] = np.random.choice([2, 3, 4], n_normal, p=[0.1, 0.8, 0.1])  # status
            normal_data[:, 13] = np.random.choice([0, 1], n_normal, p=[0.9, 0.1])  # is_error
            normal_data[:, 14] = np.random.lognormal(8, 1, n_normal)       # response_size
            normal_data[:, 15] = np.random.choice([10, 172, 192], n_normal)  # ip_octet_1
            normal_data[:, 16] = np.random.randint(1, 255, n_normal)       # ip_octet_4
            normal_data[:, 17] = 1                                          # is_private
            normal_data[:, 18] = np.random.normal(100, 20, n_normal)       # ua_length
            normal_data[:, 19] = 0                                          # is_scanner
            
            # Anomalias: ataques típicos
            anomaly_data = np.zeros((n_anomaly, n_features))
            anomaly_data[:, 0] = np.random.choice(range(0, 6), n_anomaly)  # hora anormal
            anomaly_data[:, 1] = np.random.choice(range(5, 7), n_anomaly)  # fim de semana
            anomaly_data[:, 2] = np.random.normal(500, 200, n_anomaly)     # requests longos
            anomaly_data[:, 3] = np.random.normal(200, 100, n_anomaly)     # urls longos
            anomaly_data[:, 4] = np.random.poisson(30, n_anomaly)          # muitos special_chars
            anomaly_data[:, 5] = np.random.poisson(5, n_anomaly)
            anomaly_data[:, 6] = np.random.poisson(10, n_anomaly)
            anomaly_data[:, 7] = np.random.poisson(5, n_anomaly)
            anomaly_data[:, 8] = np.random.choice([0, 1], n_anomaly, p=[0.3, 0.7])  # sql
            anomaly_data[:, 9] = np.random.choice([0, 1], n_anomaly, p=[0.4, 0.6])  # xss
            anomaly_data[:, 10] = np.random.choice([0, 1], n_anomaly, p=[0.5, 0.5])  # traversal
            anomaly_data[:, 11] = 1
            anomaly_data[:, 12] = np.random.choice([4, 5], n_anomaly)
            anomaly_data[:, 13] = 1
            anomaly_data[:, 14] = np.random.lognormal(5, 2, n_anomaly)
            anomaly_data[:, 15] = np.random.randint(1, 255, n_anomaly)
            anomaly_data[:, 16] = np.random.randint(1, 255, n_anomaly)
            anomaly_data[:, 17] = 0
            anomaly_data[:, 18] = np.random.choice([20, 150], n_anomaly)
            anomaly_data[:, 19] = np.random.choice([0, 1], n_anomaly, p=[0.3, 0.7])
            
            return np.vstack([normal_data, anomaly_data])
        
        else:
            # Dados genéricos
            normal_data = np.random.randn(int(n_samples * 0.9), n_features)
            anomaly_data = np.random.randn(int(n_samples * 0.1), n_features) * 3 + 5
            return np.vstack([normal_data, anomaly_data])
    
    def save_model(self, profile_id: str, model: 'IsolationForest', scaler: 'StandardScaler'):
        """Guarda modelo."""
        if not SKLEARN_AVAILABLE:
            return
        
        model_path = self.models_dir / f"pretrained_{profile_id}.pkl"
        scaler_path = self.models_dir / f"pretrained_{profile_id}_scaler.pkl"
        
        joblib.dump(model, model_path)
        joblib.dump(scaler, scaler_path)
        
        # Metadata
        meta = {
            'profile_id': profile_id,
            'profile_name': self.PROFILES[profile_id]['name'],
            'created_at': datetime.now().isoformat(),
            'contamination': self.PROFILES[profile_id]['contamination']
        }
        with open(self.models_dir / f"pretrained_{profile_id}_meta.json", 'w') as f:
            json.dump(meta, f, indent=2)
        
        print(f"[PretrainedModels] Modelo guardado: {model_path}")
    
    def load_model(self, profile_id: str) -> Optional[Tuple]:
        """Carrega modelo pré-treinado."""
        if not SKLEARN_AVAILABLE:
            return None
        
        # Verificar cache
        if profile_id in self.loaded_models:
            return self.loaded_models[profile_id]
        
        model_path = self.models_dir / f"pretrained_{profile_id}.pkl"
        scaler_path = self.models_dir / f"pretrained_{profile_id}_scaler.pkl"
        
        if model_path.exists() and scaler_path.exists():
            try:
                model = joblib.load(model_path)
                scaler = joblib.load(scaler_path)
                self.loaded_models[profile_id] = (model, scaler)
                print(f"[PretrainedModels] Modelo carregado: {profile_id}")
                return (model, scaler)
            except Exception as e:
                print(f"[PretrainedModels] Erro ao carregar: {e}")
        
        return None
    
    def get_or_create_model(self, profile_id: str) -> Optional[Tuple]:
        """Obtém modelo existente ou cria novo."""
        # Tentar carregar
        result = self.load_model(profile_id)
        if result:
            return result
        
        # Criar novo
        result = self.create_pretrained_model(profile_id)
        if result:
            model, scaler = result
            self.save_model(profile_id, model, scaler)
            self.loaded_models[profile_id] = result
            return result
        
        return None
    
    def predict(self, profile_id: str, features: np.ndarray) -> Optional[np.ndarray]:
        """Faz predição com modelo pré-treinado."""
        result = self.get_or_create_model(profile_id)
        if not result:
            return None
        
        model, scaler = result
        
        # Normalizar
        features_scaled = scaler.transform(features.reshape(1, -1) if features.ndim == 1 else features)
        
        # Predizer (-1 = anomalia, 1 = normal)
        predictions = model.predict(features_scaled)
        scores = model.decision_function(features_scaled)
        
        return {
            'predictions': predictions,
            'scores': scores,
            'is_anomaly': predictions == -1
        }
    
    def create_all_models(self):
        """Cria todos os modelos pré-treinados."""
        print("[PretrainedModels] A criar todos os modelos...")
        for profile_id in self.PROFILES:
            self.get_or_create_model(profile_id)
        print("[PretrainedModels] Todos os modelos criados!")


# Teste
if __name__ == "__main__":
    print("🤖 Teste de Modelos Pré-treinados")
    
    pm = PretrainedModels("test_models")
    
    # Listar perfis
    print("\nPerfis disponíveis:")
    for profile in pm.get_available_profiles():
        print(f"  - {profile['id']}: {profile['name']}")
    
    # Criar modelo web_server
    print("\nA criar modelo web_server...")
    result = pm.get_or_create_model('web_server')
    
    if result:
        # Testar predição
        test_features = np.array([
            10, 1, 100, 50, 3, 2, 3, 1, 0, 0, 0, 0, 2, 0, 5000, 192, 100, 1, 100, 0  # Normal
        ])
        pred = pm.predict('web_server', test_features)
        print(f"Predição (normal): {pred}")
        
        test_features_anomaly = np.array([
            3, 6, 1000, 500, 50, 10, 20, 10, 1, 1, 1, 1, 5, 1, 100, 45, 200, 0, 20, 1  # Anomalia
        ])
        pred = pm.predict('web_server', test_features_anomaly)
        print(f"Predição (anomalia): {pred}")
    
    print("\n✅ Teste concluído!")
