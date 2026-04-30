# 📖 Necronomicon SIEM

**The Book of the Dead - Unifying All Forbidden Knowledge**

> *"That is not dead which can eternal lie, and with strange aeons even death may die."
> — H.P. Lovecraft*

## 📋 Descripción

**Necronomicon** es un SIEM (Security Information and Event Management) que unifica todas las herramientas de seguridad del ecosistema **Providence** en un solo dashboard.

## 🎯 Objetivo

Centralizar y correlacionar eventos de seguridad de múltiples fuentes para:
- 🔍 **Detección temprana** de ataques coordinados
- 📊 **Visualización unificada** del estado de seguridad
- 🚨 **Alertas inteligentes** basadas en correlación
- 🌍 **Mapa geográfico** de atacantes

## 🏗️ Arquitectura

```
┌─────────────────────────────────────────────────────────────┐
│                    📖 NECRONOMICON SIEM                       │
├─────────────────────────────────────────────────────────────┤
│                                                                │
│  🎯 Arkham        🛡️ Providence     ⚔️ Security              │
│  CTF Agent           SOC              Enforcer                │
│      │                  │                  │                 │
│      └──────────────────┼──────────────────┘                 │
│                         ↓                                      │
│              ┌─────────────────────┐                          │
│              │   Necronomicon    │                          │
│              │   API Server      │                          │
│              │   (Port 7000)      │                          │
│              └────────┬──────────┘                          │
│                       ↓                                       │
│              ┌─────────────────────┐                          │
│              │   Dashboard Web   │                          │
│              │   + Correlator    │                          │
│              └─────────────────────┘                          │
│                                                                │
└─────────────────────────────────────────────────────────────┘
```

## 🚀 Quick Start

### Requisitos
- Python 3.8+
- Flask

### Instalación

```bash
# Clonar repositorio
git clone https://github.com/rhizor/necronomicon.git
cd necronomicon

# Instalar dependencias
pip install -r requirements.txt

# Iniciar servidor
python -m necronomicon
```

### Acceder al Dashboard

Abre tu navegador en: **http://localhost:7000**

## 📡 API Endpoints

### Enviar eventos

```bash
curl -X POST http://localhost:7000/api/events \
  -H "Content-Type: application/json" \
  -d '{
    "source": "rlyeh",
    "event_type": "ssh_attack",
    "severity": "high",
    "title": "SSH brute force attempt",
    "description": "Multiple failed login attempts",
    "source_ip": "192.168.1.100",
    "raw_data": {
      "username": "root",
      "password": "admin123"
    }
  }'
```

### Obtener estadísticas

```bash
curl http://localhost:7000/api/stats
```

### Obtener eventos

```bash
# Todos los eventos
curl http://localhost:7000/api/events

# Filtrados por source
curl "http://localhost:7000/api/events?source=rlyeh"

# Filtrados por severidad
curl "http://localhost:7000/api/events?severity=critical"
```

## 🎯 Fuentes Soportadas

| Fuente | Descripción | Tipo de Eventos |
|--------|-------------|-----------------|
| 🎯 **Arkham** | CTF Agent | Flags found, challenges completed |
| 🛡️ **Providence SOC** | Security Operations | Infrastructure alerts |
| ⚔️ **Security Enforcer** | Policy Enforcement | Blocked IPs, CVEs, attacks |
| 🔮 **Azathoth TI** | Threat Intelligence | IOCs, threat data |
| 🎭 **Rlyeh** | Honeypot | SSH attacks, web attacks, malware |

## 📊 Dashboard Features

### Estadísticas en Tiempo Real
- Total de eventos
- Eventos últimas 24h / 1h
- Eventos por severidad (Critical, High, Medium, Low)
- Eventos por fuente
- Alertas abiertas
- Incidentes activos

### Visualizaciones
- 📈 Timeline de eventos
- 🌍 Distribución geográfica de atacantes
- 📋 Lista de eventos recientes
- ⚠️ Alertas activas

### Correlación
Detecta automáticamente:
- Misma IP atacando múltiples fuentes
- Patrones de ataque similares
- Actividad coordinada

## 🔧 Configuración

### Integración con herramientas

#### Desde R'lyeh Honeypot:
```python
import requests

event = {
    "source": "rlyeh",
    "event_type": "ssh_brute_force",
    "severity": "high",
    "title": "SSH brute force detected",
    "source_ip": attacker_ip,
    "raw_data": session_data
}

requests.post("http://necronomicon:7000/api/events", json=event)
```

#### Desde Security Enforcer:
```python
requests.post("http://necronomicon:7000/api/events", json={
    "source": "security_enforcer",
    "event_type": "ip_blocked",
    "severity": "medium",
    "title": f"IP {ip} blocked",
    "source_ip": ip,
    "description": reason
})
```

## 📁 Estructura del Proyecto

```
necronomicon/
├── src/
│   └── necronomicon/
│       ├── __init__.py          # Package init
│       ├── __main__.py          # Entry point
│       ├── api.py               # Flask API + Dashboard
│       ├── models.py            # Data models
│       ├── storage.py           # In-memory storage
│       └── correlator.py        # Event correlation
├── requirements.txt             # Dependencies
└── README.md                    # This file
```

## 🛡️ Seguridad

- **No almacena secrets** (solo metadatos de eventos)
- **Procesamiento local** (no envía datos externos)
- **Rate limiting** (configurable)
- **CORS habilitado** para frontend

## 📈 Roadmap

- [ ] Integración con Elasticsearch
- [ ] Dashboard React/Vue.js avanzado
- [ ] Machine Learning para detección de anomalías
- [ ] Export a PDF/CSV
- [ ] Alertas Slack/Discord/Telegram
- [ ] Autenticación y RBAC

## 🤝 Integración con Ecosistema Providence

```
Providence Security Ecosystem:

🔍 Yellow Sign (Secrets Detection)
    ↓
🎭 R'lyeh (Honeypot Detection)
    ↓
⚔️ Security Enforcer (Policy Enforcement)
    ↓
🔮 Azathoth TI (Threat Intelligence)
    ↓
📖 Necronomicon (Unified SIEM) ← YOU ARE HERE
    ↓
🛡️ Providence SOC (Operations Center)
    ↓
🎯 Arkham (CTF Training)
```

## 📚 Referencias

- [H.P. Lovecraft - The Call of Cthulhu](https://en.wikipedia.org/wiki/The_Call_of_Cthulhu)
- [SIEM - Wikipedia](https://en.wikipedia.org/wiki/Security_information_and_event_management)
- [Flask Documentation](https://flask.palletsprojects.com/)

---

**Versión:** 1.0.0  
**Autor:** rhizor  
**Licencia:** MIT  
**Parte del Ecosistema Providence**

*"Ph'nglui mglw'nafh Cthulhu R'lyeh wgah'nagl fhtagn"* 🦑
