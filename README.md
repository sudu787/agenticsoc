<div align="center">

# 🛡️ SecureFlow AI
### Autonomous Security Operations Platform

> *"197 days to detect a breach. We built the system that does it in 4 seconds."*

![Demo Animation](screenshots/demo.gif)

[![Python](https://img.shields.io/badge/Python-3.10-blue?logo=python&logoColor=white)](#)
[![Next.js](https://img.shields.io/badge/Next.js-16.2-black?logo=next.js&logoColor=white)](#)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi&logoColor=white)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](#)
[![FlowZint 2026](https://img.shields.io/badge/FlowZint%20AI%20Hackathon-2026-8b5cf6)](#)

**[🎬 Watch Demo](DEMO.md) · [⚡ Quick Start](#quick-start) · [📐 Architecture](ARCHITECTURE.md) · [🤖 Agents](AGENTS.md) · [👨‍⚖️ Judges](JUDGES.md)**

</div>

---

## 🚨 The Problem

Modern Security Operations Centers are drowning.

- **10,000–100,000 alerts per day** — analysts meaningfully investigate < 0.05%
- **197-day average breach detection time** — attackers operate undetected for months  
- **$4.5M average breach cost** — 69 days to contain after detection
- **3.4M unfilled cybersecurity jobs globally** — teams are permanently understaffed
- **Zero institutional memory** — when an analyst leaves, their knowledge leaves with them

Existing tools (SIEMs, EDRs, SOARs) generate data. They do not *think*, *connect*, or *remember*.

---

## 💡 The Solution

**SecureFlow AI** is an autonomous security team — five specialized AI agents permanently online,
sharing a Security Knowledge Graph and organizational memory, continuously learning from every attack.

```
Threat Detected (4 seconds)
       ↓
🎯 Triage Agent classifies priority
       ↓
🔍 Investigation Agent traces attack chain
       ↓
🌐 Threat Intel Agent enriches from graph
       ↓
🧠 Memory Agent recalls past incidents
       ↓
🔮 Risk Agent predicts cascade impact
       ↓
⚡ Response Agent recommends + executes (with approval)
       ↓
📊 Executive Dashboard auto-generates CISO report
```

**What makes SecureFlow AI unique:**
1. **Graph + Memory combination** — No SOC platform connects knowledge graph intelligence with organizational episodic memory
2. **XAI on every autonomous action** — Every AI decision shows its evidence chain before acting
3. **Predictive security** — We don't just detect what happened; we forecast what's about to happen

---

## 🏗️ Architecture

![System Architecture](docs/architecture/system-architecture.png)

| Layer | Technology | Purpose |
|---|---|---|
| **Frontend** | Next.js 16, React, Vanilla CSS | 20-page enterprise dashboard |
| **Backend** | FastAPI, Python 3.10, SQLAlchemy | REST API + agent orchestration |
| **Knowledge Graph** | NetworkX, custom GraphRAG | Entity relationships + risk propagation |
| **Memory** | SQLite + semantic indexing | Episodic incident memory |
| **RAG Engine** | GraphRAG Fusion | MITRE ATT&CK grounded intelligence |
| **Database** | SQLite (→ PostgreSQL in prod) | Event, Alert, Incident, Ticket storage |

---

## 🤖 AI Agents

| Agent | Role | Speed | MITRE Integration |
|---|---|---|---|
| 🎯 **Triage** | Classify alerts P1–P4, route to workflows | < 2s | Technique mapping |
| 🔍 **Investigation** | Correlate alerts, trace attack chains, collect evidence | < 5s | Kill chain analysis |
| 🌐 **Threat Intelligence** | Enrich IOCs, identify threat actors via graph | < 3s | Actor attribution |
| 🧠 **Memory** | Recall similar past incidents, surface past mitigations | < 1s | Pattern matching |
| 🔮 **Risk Prediction** | Cascade risk scoring, attack probability forecast | < 4s | Impact prediction |
| ⚡ **Autonomous Response** | Recommend + execute containment with XAI + human approval | On approval | Response playbooks |

---

## 🕸️ Security Knowledge Graph

The graph is the intelligence core of SecureFlow AI.

- **90 nodes** across 17 entity types (IPs, Users, Devices, Assets, CVEs, Threat Actors, MITRE Techniques...)
- **234 relationships** mapping attack paths, vulnerabilities, and threat actor TTPs
- **Real-time risk propagation** — computes cascade impact from any compromised entity
- **GraphRAG fusion** — combines graph traversal with RAG retrieval for grounded intelligence

```
APT29 ──uses──► T1110 (Brute Force) ──targets──► VPN-Gateway
  └──deploys──► Akira-Ransomware ──encrypts──► DB-PROD-01
       └──linked_to──► CVE-2024-3094 ──affects──► WKSTN-047
```

---

## 🧠 Organizational Memory

SecureFlow AI never forgets. The Memory Agent stores every incident as a semantic embedding
and retrieves similar past events during new investigations.

```
New Alert: Brute Force from 185.220.101.34
    ↓
Memory Query: similarity search (cosine distance)
    ↓
Match Found: INC-104 (March 2024, similarity: 0.89)
    ↓
Recall: "VPN geo-block + forced password reset resolved this"
    ↓
Apply: learned mitigation template to new incident
```

---

## 📊 Executive Dashboard

The CISO gets a real-time boardroom briefing — no analyst hours, no report writing.

- **Live Risk Score** — org-wide gauge computed from graph traversal
- **5-Framework Compliance** — NIST, CIS, ISO 27001, SOC 2, PCI DSS auto-mapped
- **AI Threat Forecast** — Next 7 days predicted attacks with probability scores
- **One-Click CISO Report** — Full boardroom PDF generated from live data

---

## 🎮 Demo: Operation NightOwl

Navigate to `/demo` and click **🚨 Launch Ransomware Attack** to trigger:

| Stage | Technique | Description |
|---|---|---|
| 1 | T1110 | 47 VPN credential stuffing attempts from APT29 IP |
| 2 | T1078 | Successful login with compromised credential |
| 3 | T1068 | Privilege escalation via CVE-2024-3094 |
| 4 | T1021 | WMI lateral movement WKSTN-047 → API-GW-01 |
| 5 | T1204 | Akira ransomware dropped (YARA match) |
| 6 | T1071 | CobaltStrike C2 beacon to 91.121.87.18 |
| 7 | T1074 | 2.3GB customer data staged |
| 8 | T1048 | Data exfiltrated via TOR exit node |
| 9 | T1486 | 3,847 files encrypted (.akira extension) |

All 5 AI agents respond autonomously. Navigate to `/graph` to see risk propagation.

---

## Screenshots

| War Room | Knowledge Graph |
|---|---|
| ![War Room](screenshots/war-room.png) | ![Graph](screenshots/knowledge-graph.png) |

| Autonomous Response + XAI | Executive Dashboard |
|---|---|
| ![XAI](screenshots/autonomous-xai.png) | ![Executive](screenshots/executive-dashboard.png) |

| Risk Prediction | Compliance Intelligence |
|---|---|
| ![Risk](screenshots/risk-prediction.png) | ![Compliance](screenshots/compliance.png) |

---

## ⚡ Quick Start

### Prerequisites
- Python 3.10+
- Node.js 18+
- Git

### 1. Clone
```bash
git clone https://github.com/sudu/agenticsoc
cd secureflow-ai
```

### 2. Backend
```bash
cd backend
python -m venv venv

# Windows
.\venv\Scripts\Activate.ps1

# macOS/Linux  
source venv/bin/activate

pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

### 3. Frontend
```bash
cd frontend
npm install
npm run dev
```

### 4. Open
```
http://localhost:3000        ← Full platform
http://localhost:3000/demo  ← Launch ransomware simulation
http://localhost:8000/docs  ← FastAPI interactive API docs
```

---

## 🏆 Innovation Highlights

| Innovation | What It Is | Why It's Novel |
|---|---|---|
| **GraphRAG Fusion** | Graph traversal + vector RAG combined | No existing SOC tool does both simultaneously |
| **Episodic Memory** | Semantic search over past incidents | Prevents repeated mistakes across analyst shifts |
| **XAI Evidence Chain** | Every AI action cites its reasoning | Makes autonomous security trustworthy |
| **Cascade Risk Propagation** | Real-time graph-computed blast radius | Predicts attack path before completion |
| **Continuous Compliance** | Auto-maps live alerts to 5 frameworks | Replaces quarterly manual compliance audits |
| **Predictive Threat Intel** | Probability forecasts for future attacks | Forward-looking, not reactive |

---

## 🗺️ Roadmap

- [ ] Real SIEM connector (Splunk, QRadar, Microsoft Sentinel)
- [ ] Federated threat graph sharing between organizations
- [ ] Natural language SOC interface ("Show me all APT29 activity this week")
- [ ] Autonomous playbook generation from memory patterns
- [ ] Mobile CISO app with push alerts
- [ ] LLM fine-tuning on organization-specific threat data

---

## 🙋 Team

Built at **FlowZint AI Hackathon 2026** by [Your Team Name]

---

## 📄 License

MIT License — see [LICENSE](LICENSE)
