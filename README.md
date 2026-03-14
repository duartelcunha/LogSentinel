# 🦉 Log Sentinel v2.0

## Sistema de Análise e Deteção de Anomalias em Logs

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-Academic-green.svg)](LICENSE)
[![ISTEC](https://img.shields.io/badge/ISTEC-2025/2026-orange.svg)](https://istec.pt)

**Autor:** Duarte Cunha (Nº 2024271)  
**Instituição:** ISTEC - Instituto Superior de Tecnologias Avançadas de Lisboa  
**Ano Letivo:** 2025/2026

---

## 📋 Sobre o Projeto

O Log Sentinel é um sistema avançado de análise e deteção de anomalias em ficheiros de log, desenvolvido como projeto académico. Utiliza técnicas de análise de padrões, Machine Learning e correlação de eventos para identificar potenciais ameaças de segurança.

### ✨ Funcionalidades

- 📊 **Dashboard em Tempo Real** - Métricas e visualizações atualizadas
- 🔔 **Sistema de Alertas** - Notificações desktop para ameaças críticas
- 📈 **Timeline Interativa** - Visualização temporal de eventos
- 🔗 **Correlação de Eventos** - Deteção de ataques multi-vetor
- 📄 **Exportação de Relatórios** - PDF, CSV, JSON, DOCX
- 🔌 **Sistema de Plugins** - Extensibilidade para deteções customizadas
- 🤖 **Machine Learning** - Isolation Forest para deteção de anomalias
- 🎨 **Design Profissional** - Interface moderna e intuitiva

### 🛡️ Tipos de Ataques Detetados

| Ataque | Severidade |
|--------|------------|
| SQL Injection | CRITICAL |
| Command Injection | CRITICAL |
| XSS (Cross-Site Scripting) | HIGH |
| Path Traversal | HIGH |
| Brute Force | HIGH |
| DDoS | CRITICAL |
| Scanner Detection | MEDIUM |
| LFI/RFI | CRITICAL |
| XXE | CRITICAL |

---

## 🚀 Instalação Rápida

### Requisitos

- Python 3.8+
- 4GB RAM (mínimo)
- Windows 10+, Linux ou macOS

### Passos

```bash
# 1. Extrair o projeto
unzip LogSentinel_v2.zip
cd LogSentinel_v2

# 2. Executar instalador
python install.py

# 3. Iniciar aplicação
python main.py
```

O instalador irá:
- ✅ Verificar Python
- ✅ Instalar dependências
- ✅ Criar diretórios necessários
- ✅ Criar atalho no Desktop

---

## 📖 Como Usar

### 1. Carregar um Ficheiro de Log

Clique em **"Carregar Log"** e selecione um ficheiro `.log` ou `.txt`.

### 2. Iniciar Análise

Clique em **"Iniciar Análise"** para processar o ficheiro.

### 3. Explorar Resultados

- **Dashboard**: Visão geral das métricas
- **Alertas**: Lista de anomalias detetadas
- **Timeline**: Eventos ao longo do tempo
- **Detalhes**: Relatório textual completo
- **ML & Plugins**: Configurações avançadas

### 4. Exportar Relatório

Clique em **"Exportar Relatório"** e escolha o formato desejado.

---

## 📁 Estrutura do Projeto

```
LogSentinel_v2/
├── main.py              # Ponto de entrada
├── install.py           # Instalador
├── requirements.txt     # Dependências
├── src/
│   ├── core/            # Motor de deteção
│   ├── gui/             # Interface gráfica
│   ├── ml/              # Machine Learning
│   ├── plugins/         # Sistema de plugins
│   └── utils/           # Utilitários
├── data/                # Dados da aplicação
├── assets/              # Recursos gráficos
└── docs/                # Documentação
```

---

## 🔧 Tecnologias Utilizadas

| Tecnologia | Utilização |
|------------|------------|
| Python 3.8+ | Linguagem principal |
| CustomTkinter | Interface gráfica |
| SQLite | Base de dados |
| scikit-learn | Machine Learning |
| ReportLab | Geração de PDFs |
| python-docx | Geração de Word |

---

## 📚 Documentação

A documentação técnica completa está disponível em:
- `docs/DOCUMENTATION.md` - Documentação técnica detalhada
- `docs/API.md` - Referência da API (em desenvolvimento)

---

## 🎓 Informações Académicas

Este projeto foi desenvolvido no âmbito da unidade curricular de **Segurança Informática** do curso de **Engenharia Informática** do ISTEC.

### Autor

**Duarte Cunha**  
Número de Aluno: 2024271  
Email: [contacto académico]

### Orientação

ISTEC - Instituto Superior de Tecnologias Avançadas de Lisboa  
Ano Letivo: 2025/2026

---

## 📝 Licença

Este projeto é desenvolvido para fins académicos. Todos os direitos reservados.

---

## 🦉 Screenshots

### Splash Screen
![Splash](docs/images/splash.png)

### Dashboard
![Dashboard](docs/images/dashboard.png)

### Alertas
![Alerts](docs/images/alerts.png)

---

**Log Sentinel v2.0** 
