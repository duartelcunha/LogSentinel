# Log Sentinel v2.0 - Documentação Técnica

## Sistema de Análise e Deteção de Anomalias em Logs

**Autor:** Duarte Cunha (Nº 2024271)  
**Instituição:** ISTEC - Instituto Superior de Tecnologias Avançadas de Lisboa  
**Ano Letivo:** 2025/2026  
**Versão:** 2.0.0

---

## Índice

1. [Introdução](#1-introdução)
2. [Arquitetura do Sistema](#2-arquitetura-do-sistema)
3. [Instalação](#3-instalação)
4. [Estrutura do Projeto](#4-estrutura-do-projeto)
5. [Módulos Principais](#5-módulos-principais)
6. [Machine Learning](#6-machine-learning)
7. [Sistema de Plugins](#7-sistema-de-plugins)
8. [Interface Gráfica](#8-interface-gráfica)
9. [Base de Dados](#9-base-de-dados)
10. [Exportação de Relatórios](#10-exportação-de-relatórios)
11. [Guia de Utilização](#11-guia-de-utilização)
12. [API de Desenvolvimento](#12-api-de-desenvolvimento)
13. [Conclusões](#13-conclusões)

---

## 1. Introdução

### 1.1 Objetivo

O Log Sentinel é um sistema avançado de análise e deteção de anomalias em ficheiros de log, desenvolvido para identificar potenciais ameaças de segurança através de:

- Análise de padrões com expressões regulares
- Análise temporal de eventos
- Machine Learning (Isolation Forest e Random Forest)
- Correlação automática de eventos
- Sistema extensível de plugins

### 1.2 Funcionalidades Principais

| Funcionalidade | Descrição |
|----------------|-----------|
| Dashboard em Tempo Real | Métricas e gráficos atualizados automaticamente |
| Sistema de Alertas | Notificações desktop para ameaças críticas |
| Timeline Interativa | Visualização temporal de eventos |
| Correlação de Eventos | Deteção automática de ataques multi-vetor |
| Exportação de Relatórios | PDF, CSV, JSON, DOCX |
| Sistema de Plugins | Extensibilidade para deteções customizadas |
| Machine Learning | Deteção de anomalias não supervisionada |

### 1.3 Tipos de Ataques Detetados

- SQL Injection
- Cross-Site Scripting (XSS)
- Path Traversal
- Command Injection
- Brute Force
- DDoS
- Scanner Detection
- Local/Remote File Inclusion (LFI/RFI)
- XML External Entity (XXE)
- Privilege Escalation

---

## 2. Arquitetura do Sistema

### 2.1 Visão Geral

```
┌─────────────────────────────────────────────────────────────────┐
│                        LOG SENTINEL v2.0                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐ │
│  │   GUI       │    │   Core      │    │   ML Module         │ │
│  │  (Tkinter)  │◄──►│  (Engine)   │◄──►│  (scikit-learn)     │ │
│  └─────────────┘    └─────────────┘    └─────────────────────┘ │
│         │                  │                     │              │
│         │                  ▼                     │              │
│         │          ┌─────────────┐               │              │
│         │          │   Parser    │               │              │
│         │          │  (Regex)    │               │              │
│         │          └─────────────┘               │              │
│         │                  │                     │              │
│         ▼                  ▼                     ▼              │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                    Database (SQLite)                     │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              │                                  │
│         ┌────────────────────┼────────────────────┐            │
│         ▼                    ▼                    ▼            │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────┐    │
│  │   Plugins   │    │  Exporter   │    │   Correlator    │    │
│  │   System    │    │  (Reports)  │    │    (Events)     │    │
│  └─────────────┘    └─────────────┘    └─────────────────┘    │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 2.2 Padrão de Design

O sistema segue os seguintes padrões:

- **MVC (Model-View-Controller):** Separação entre dados, lógica e interface
- **Observer:** Callbacks para notificação de eventos
- **Strategy:** Diferentes algoritmos de deteção
- **Plugin Architecture:** Extensibilidade através de plugins

### 2.3 Fluxo de Dados

```
Log File → Parser → Detection Engine → Database → GUI/Reports
                          ↓
                    ML Predictor
                          ↓
                     Plugins
```

---

## 3. Instalação

### 3.1 Requisitos do Sistema

- Python 3.8 ou superior
- 4GB RAM (mínimo)
- 500MB espaço em disco
- Sistema Operativo: Windows 10+, Linux, macOS

### 3.2 Dependências

```
customtkinter>=5.2.0    # Interface gráfica
pillow>=10.0.0          # Processamento de imagens
scikit-learn>=1.3.0     # Machine Learning
numpy>=1.24.0           # Computação numérica
pandas>=2.0.0           # Manipulação de dados
joblib>=1.3.0           # Persistência de modelos
reportlab>=4.0.0        # Geração de PDFs
python-docx>=1.0.0      # Geração de Word
openpyxl>=3.1.0         # Excel
plyer>=2.1.0            # Notificações desktop
```

### 3.3 Instalação Rápida

```bash
# Clonar/extrair projeto
cd LogSentinel_v2

# Executar instalador
python install.py

# Ou manualmente:
pip install -r requirements.txt
python main.py
```

### 3.4 Criação de Executável

```bash
# Instalar PyInstaller
pip install pyinstaller

# Criar executável
pyinstaller LogSentinel.spec

# O executável estará em dist/LogSentinel
```

---

## 4. Estrutura do Projeto

```
LogSentinel_v2/
├── main.py                 # Ponto de entrada
├── install.py              # Script de instalação
├── requirements.txt        # Dependências
├── LogSentinel.spec        # Config PyInstaller
│
├── src/                    # Código fonte
│   ├── core/               # Módulos principais
│   │   ├── __init__.py
│   │   ├── database.py     # Gestão SQLite
│   │   ├── engine.py       # Motor de deteção
│   │   ├── parser.py       # Parser de logs
│   │   └── exporter.py     # Exportação de relatórios
│   │
│   ├── gui/                # Interface gráfica
│   │   ├── __init__.py
│   │   ├── main_window.py  # Janela principal
│   │   ├── components.py   # Componentes UI
│   │   └── splash.py       # Splash screen
│   │
│   ├── ml/                 # Machine Learning
│   │   ├── __init__.py
│   │   └── anomaly_detector.py
│   │
│   ├── plugins/            # Sistema de plugins
│   │   ├── __init__.py
│   │   └── plugin_system.py
│   │
│   └── utils/              # Utilitários
│       ├── __init__.py
│       ├── config.py       # Configurações
│       └── theme.py        # Tema visual
│
├── data/                   # Dados da aplicação
│   ├── logs/               # Logs de exemplo
│   ├── models/             # Modelos ML
│   └── reports/            # Relatórios gerados
│
├── assets/                 # Recursos
│   └── icons/              # Ícones
│
└── docs/                   # Documentação
    └── DOCUMENTATION.md    # Este ficheiro
```

---

## 5. Módulos Principais

### 5.1 Parser (parser.py)

O parser suporta múltiplos formatos de log:

| Formato | Padrão |
|---------|--------|
| Syslog | RFC 3164/5424 |
| Auth.log | Linux authentication |
| Apache/Nginx Access | Combined Log Format |
| Apache/Nginx Error | Standard error format |
| JSON | Structured logs |
| Genérico | Auto-detect |

**Exemplo de uso:**

```python
from src.core.parser import LogParser, LogEntry

parser = LogParser()
for entry in parser.parse_file("access.log"):
    print(f"IP: {entry.source_ip}")
    print(f"Ataques detetados: {entry.extra.get('attack_indicators')}")
```

### 5.2 Detection Engine (engine.py)

Motor de deteção com múltiplos algoritmos:

```python
from src.core.engine import DetectionEngine, Anomaly

engine = DetectionEngine(db)

# Callback para anomalias
def on_anomaly(anomaly: Anomaly):
    print(f"Detetado: {anomaly.anomaly_type.value}")

engine.on_anomaly(on_anomaly)

# Analisar ficheiro
anomalies = engine.analyze_file("auth.log", session_id="123")
```

### 5.3 Database (database.py)

Gestão de dados com SQLite:

**Tabelas principais:**

| Tabela | Descrição |
|--------|-----------|
| anomalies | Anomalias detetadas |
| sessions | Sessões de análise |
| ip_stats | Estatísticas por IP |
| timeline | Eventos temporais |
| correlations | Correlações de ataques |
| alerts | Sistema de alertas |
| plugins | Plugins instalados |
| ml_training_data | Dados de treino ML |

---

## 6. Machine Learning

### 6.1 Arquitetura ML

```
                    ┌─────────────────┐
                    │  Log Entry      │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │ Feature         │
                    │ Extractor       │
                    │ (20 features)   │
                    └────────┬────────┘
                             │
              ┌──────────────┴──────────────┐
              │                             │
     ┌────────▼────────┐           ┌────────▼────────┐
     │ Isolation       │           │ Random          │
     │ Forest          │           │ Forest          │
     │ (Anomaly)       │           │ (Classifier)    │
     └────────┬────────┘           └────────┬────────┘
              │                             │
              └──────────────┬──────────────┘
                             │
                    ┌────────▼────────┐
                    │ ML Prediction   │
                    │ - is_anomaly    │
                    │ - score         │
                    │ - type          │
                    └─────────────────┘
```

### 6.2 Features Extraídas

| # | Feature | Descrição |
|---|---------|-----------|
| 1 | hour_of_day | Hora do evento (0-23) |
| 2 | day_of_week | Dia da semana (0-6) |
| 3 | request_length | Tamanho do request |
| 4 | url_length | Tamanho da URL |
| 5 | num_special_chars | Caracteres especiais |
| 6 | num_dots | Número de pontos |
| 7 | num_slashes | Número de barras |
| 8 | num_params | Parâmetros URL |
| 9 | has_sql_keywords | Keywords SQL |
| 10 | has_script_tags | Tags script |
| 11 | has_path_traversal | Path traversal |
| 12 | has_encoded_chars | Chars encoded |
| 13 | status_code_class | Classe HTTP |
| 14 | is_error_status | É erro |
| 15 | response_size | Tamanho resposta |
| 16 | ip_octet_1 | Primeiro octeto IP |
| 17 | ip_octet_4 | Último octeto IP |
| 18 | is_private_ip | IP privado |
| 19 | user_agent_length | Tamanho UA |
| 20 | is_known_scanner | Scanner conhecido |

### 6.3 Treino do Modelo

```python
from src.ml import AnomalyDetector

detector = AnomalyDetector()

# Treinar com dados
entries = [...]  # Lista de dicionários
result = detector.train_anomaly_detector(entries, contamination=0.1)

# Predição
prediction = detector.predict(entry)
if prediction.is_anomaly:
    print(f"Anomalia! Score: {prediction.confidence}")
```

---

## 7. Sistema de Plugins

### 7.1 Arquitetura de Plugins

```python
from src.plugins import BaseDetectionPlugin, DetectionResult

class MyPlugin(BaseDetectionPlugin):
    name = "Meu Plugin"
    version = "1.0"
    author = "Autor"
    description = "Descrição"
    
    def detect(self, entry: dict) -> DetectionResult:
        if "suspicious" in entry.get('message', ''):
            return DetectionResult(
                detected=True,
                anomaly_type="CUSTOM",
                severity="HIGH",
                detail="Padrão detetado"
            )
        return DetectionResult(detected=False)
```

### 7.2 Plugins Built-in

| Plugin | Descrição |
|--------|-----------|
| APIAbusePlugin | Deteta abuso de APIs |
| SensitiveDataPlugin | Deteta exposição de dados |
| AnomalousTimePlugin | Atividade fora de horário |

---

## 8. Interface Gráfica

### 8.1 Componentes

| Componente | Ficheiro | Descrição |
|------------|----------|-----------|
| LogSentinelApp | main_window.py | Janela principal |
| SplashScreen | splash.py | Tela de carregamento |
| MetricCard | components.py | Card de métricas |
| AlertItem | components.py | Item de alerta |
| TabView | components.py | Navegação por tabs |

### 8.2 Tema

O tema utiliza uma paleta de cores profissional:

```python
BG_PRIMARY = "#0f172a"      # Azul escuro
BG_SECONDARY = "#1e293b"    # Painéis
ACCENT_PRIMARY = "#3b82f6"  # Azul destaque
CRITICAL = "#ef4444"        # Vermelho
HIGH = "#f97316"            # Laranja
MEDIUM = "#eab308"          # Amarelo
LOW = "#22c55e"             # Verde
```

---

## 9. Base de Dados

### 9.1 Schema

```sql
-- Anomalias
CREATE TABLE anomalies (
    id INTEGER PRIMARY KEY,
    type TEXT NOT NULL,
    severity TEXT DEFAULT 'MEDIUM',
    source_ip TEXT,
    target TEXT,
    detail TEXT NOT NULL,
    log_line TEXT,
    log_file TEXT,
    timestamp DATETIME,
    session_id TEXT,
    score REAL DEFAULT 0.0,
    ml_score REAL,
    is_correlated INTEGER DEFAULT 0,
    correlation_group TEXT,
    reviewed INTEGER DEFAULT 0
);

-- Índices para performance
CREATE INDEX idx_anomalies_type ON anomalies(type);
CREATE INDEX idx_anomalies_severity ON anomalies(severity);
CREATE INDEX idx_anomalies_timestamp ON anomalies(timestamp);
```

---

## 10. Exportação de Relatórios

### 10.1 Formatos Suportados

| Formato | Biblioteca | Descrição |
|---------|-----------|-----------|
| PDF | ReportLab | Relatório profissional |
| CSV | csv | Dados tabulares |
| JSON | json | Dados estruturados |
| DOCX | python-docx | Documento Word |

### 10.2 Exemplo

```python
from src.core.exporter import ReportExporter

exporter = ReportExporter()
exporter.export(
    anomalies=anomaly_list,
    stats=stats_dict,
    filepath="relatorio.pdf",
    format="pdf",
    title="Relatório de Segurança"
)
```

---

## 11. Guia de Utilização

### 11.1 Análise Básica

1. Iniciar aplicação (main.py ou atalho)
2. Clicar em "Carregar Log"
3. Selecionar ficheiro de log
4. Clicar em "Iniciar Análise"
5. Explorar resultados nas tabs
6. Exportar relatório se necessário

### 11.2 Interpretação de Resultados

| Severidade | Ação Recomendada |
|------------|------------------|
| CRITICAL | Investigar imediatamente |
| HIGH | Prioridade alta |
| MEDIUM | Analisar quando possível |
| LOW | Monitorizar |

---

## 12. API de Desenvolvimento

### 12.1 Integração Programática

```python
from src.core import DatabaseManager, DetectionEngine
from src.ml import AnomalyDetector

# Configurar
db = DatabaseManager("data/sentinel.db")
engine = DetectionEngine(db, enable_ml=True)

# Analisar
anomalies = engine.analyze_file("access.log")

# Obter estatísticas
stats = engine.get_stats()
print(f"Anomalias: {stats['anomalies_detected']}")

# Correlacionar
correlations = engine.correlate_anomalies()
```

---

## 13. Conclusões

### 13.1 Resultados Alcançados

O Log Sentinel v2.0 implementa com sucesso:

- ✅ Dashboard com métricas em tempo real
- ✅ Sistema de alertas com notificações desktop
- ✅ Timeline interativa de eventos
- ✅ Correlação automática de eventos suspeitos
- ✅ Exportação multi-formato (PDF, CSV, JSON, DOCX)
- ✅ Sistema de plugins extensível
- ✅ Machine Learning para deteção de anomalias
- ✅ Interface profissional e intuitiva
- ✅ Instalador fácil de usar

### 13.2 Trabalho Futuro

- Integração com SIEM externos
- Suporte a mais formatos de log
- Dashboard web
- API REST
- Cluster de análise distribuída

---

**Log Sentinel v2.0** - Desenvolvido por Duarte Cunha (Nº 2024271)  
ISTEC - Instituto Superior de Tecnologias Avançadas de Lisboa  
Ano Letivo 2025/2026
