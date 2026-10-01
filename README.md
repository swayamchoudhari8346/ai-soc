# AI-SOC — AI-Augmented Security Operations Center

> **4th year Computer Engineering Major Project**

An AI-augmented SOC that investigates security incidents using a local LLM, retrieves knowledge via RAG, verifies response plans against deterministic policies, restricts dangerous actions via bounded autonomy, and requires human approval for high-risk remediation.

**Core principle:** AI proposes. Evidence supports. Rules verify. Safety controls constrain. Humans approve high-risk actions.

---

## Architecture

```
Security Events (simulated)
        ↓
Wazuh SIEM (Docker)
        ↓
FastAPI Backend
        ↓
AI Investigation Agent (Ollama llama3.1:8b)
   ├── RAG Knowledge Base (ChromaDB)
   ├── Log Search Tool
   └── IOC Lookup Tool
        ↓
Policy Engine (Python rules)
        ↓
Safety Engine (risk levels L0–L7)
        ↓
Human Approval (React UI)
        ↓
Remediation (simulated safe actions)
        ↓
Audit Log (PostgreSQL)
        ↓
Dashboard (React)
```

---

## Stack

| Layer | Technology |
|---|---|
| SIEM | Wazuh (Docker) |
| Backend | Python 3.12 + FastAPI 0.115 |
| Database | PostgreSQL 16 (Docker) |
| AI | Ollama + llama3.1:8b (fully local) |
| RAG | ChromaDB 0.5 + nomic-embed-text |
| Frontend | React 19 + Vite 8 |
| Containers | Docker Compose |

Everything runs locally — no cloud, no API keys, no cost.

---

## Prerequisites

- Docker + Docker Compose
- Python 3.12+
- Node.js 18+
- [Ollama](https://ollama.com) with the following models pulled:

```bash
ollama pull llama3.1:8b
ollama pull nomic-embed-text
```

- Ollama must be reachable from Docker containers. Set `OLLAMA_HOST=0.0.0.0` in the Ollama systemd service so containers can reach it via `host.docker.internal`.

---

## Quick Start

### 1. Clone and configure

```bash
git clone https://github.com/swayamchoudhari8346/ai-soc.git
cd ai-soc
cp .env.example .env   # then edit passwords if needed
```

Create a `.env` file (see `.env.example` below):

```env
POSTGRES_DB=aisoc
POSTGRES_USER=aisoc
POSTGRES_PASSWORD=aisoc_dev_password
POSTGRES_PORT=5432
BACKEND_PORT=8000
FRONTEND_PORT=3000
OLLAMA_HOST=http://host.docker.internal:11434
OLLAMA_MODEL=llama3.1:8b
OLLAMA_EMBED_MODEL=nomic-embed-text
```

### 2. Generate Wazuh SSL certificates (first time only)

```bash
docker compose -f generate-indexer-certs.yml run --rm generator
```

### 3. Start all services

```bash
docker compose up -d
```

Wait ~60 seconds for Wazuh to initialise, then check:

```bash
docker compose ps       # all containers should be Up/healthy
curl http://localhost:8000/health   # {"status":"ok","database":"ok"}
```

### 4. Start the frontend (dev mode)

```bash
cd frontend
npm install
npm run dev             # http://localhost:5173
```

---

## Services

| Service | URL | Credentials |
|---|---|---|
| Backend API | http://localhost:8000 | — |
| API Docs (Swagger) | http://localhost:8000/docs | — |
| React Dashboard | http://localhost:5173 | — |
| Wazuh Dashboard | https://localhost | admin / SecretPassword |
| Adminer (DB UI) | http://localhost:8080 | System: PostgreSQL, Server: postgres, User: aisoc |

---

## Running Attack Scenarios

Three scenarios are included. Each runs the full pipeline end-to-end.

### Scenario 1 — SSH Brute Force

```bash
python3 scenarios/e2e_test.py --approver "analyst1"
```

Expected: Brute Force Attack, MITRE T1110, disable_account held for approval.

### Scenario 2 — Suspicious PowerShell

```bash
python3 scenarios/powershell_suspicious.py --approver "analyst1"
```

Expected: T1059.001 (PowerShell), collect_logs + tag_ioc auto-executed.

### Scenario 3 — Privilege Escalation

```bash
python3 scenarios/privilege_escalation.py --approver "analyst1"
```

Expected: Privilege Escalation Attack, MITRE T1068, disable_account held for approval.

---

## Evaluation Results

All three scenarios tested against the full AI-SOC system:

| Scenario | Classification | MITRE | Confidence | Inv. Time | Actions | Policy Enforced |
|---|---|---|---|---|---|---|
| SSH Brute Force | Brute Force Attack | T1110 ✓ | 90% | ~101s | 3 | ✓ (disable_account → approval) |
| PowerShell | Cmd & Scripting: PowerShell | T1059.001 ✓ | 80% | ~100s | 2 | n/a (all L4) |
| Privilege Escalation | Privilege Escalation Attack | T1068 ✓ | 90% | ~87s | 3 | ✓ (disable_account → approval) |

**Aggregate:**
- Detection accuracy: 3/3 (100%)
- MITRE mapping accuracy: 3/3 (100%)
- Avg investigation time: ~96s
- Policy enforcement rate: 2/2 violating actions held for approval (100%)
- Unsafe auto-execution: 0 — no L5+ actions executed without approval
- RAG hit rate: 3/3 — relevant KB documents retrieved in every scenario

---

## API Reference

| Method | Path | Description |
|---|---|---|
| GET | `/health` | Health check |
| GET | `/incidents/` | List incidents (paginated) |
| GET | `/incidents/stats` | Dashboard summary stats |
| GET | `/incidents/{id}` | Incident detail with AI report |
| POST | `/alerts/ingest` | Ingest a Wazuh alert → create incident |
| POST | `/incidents/{id}/investigate` | Trigger AI investigation |
| GET | `/incidents/{id}/actions` | List actions with policy + risk decisions |
| POST | `/incidents/{id}/execute-actions` | Run safety engine on pending actions |
| GET | `/incidents/{id}/audit` | Full audit trail |
| GET | `/approvals` | Pending approval queue |
| POST | `/approvals/{id}/decide` | Approve or reject an action |
| POST | `/incidents/{id}/execute-approved` | Execute analyst-approved actions |

---

## Safety Design

### Risk Levels

| Level | Example Actions | Execution |
|---|---|---|
| L0–L1 | Read alert, search logs | Automatic |
| L2–L4 | IOC enrichment, tag IOC, collect logs | Automatic |
| L5–L6 | Kill process, isolate host, disable account | Requires human approval |
| L7 | Shutdown server, delete data | Never autonomous — blocked |

### Policy Rules

| ID | Rule | Effect |
|---|---|---|
| P001 | Isolate a critical asset | require_approval |
| P002 | Disable any admin account | require_approval |
| P003 | Shutdown any server | block |
| P004 | Recover system before forensics complete | block |

### Prompt Injection Defence

All alert data is labelled as `UNTRUSTED USER DATA` in the LLM system prompt. Instructions embedded in log fields are treated as suspicious log entries, not commands.

---

## Project Structure

```
ai-soc/
├── docker-compose.yml
├── backend/
│   ├── main.py
│   ├── requirements.txt
│   ├── models/models.py          # SQLAlchemy ORM (5 tables)
│   ├── routers/                  # FastAPI route handlers
│   └── services/
│       ├── investigation.py      # LLM agent (Ollama)
│       ├── rag.py                # ChromaDB retrieval
│       ├── policy.py             # Deterministic policy engine
│       ├── safety.py             # Risk classification + approval queue
│       └── ingestion.py          # Alert → incident pipeline
├── frontend/
│   └── src/pages/
│       ├── Dashboard.jsx
│       ├── Incidents.jsx
│       ├── IncidentDetail.jsx
│       └── Approvals.jsx
├── knowledge/
│   ├── mitre/                    # MITRE ATT&CK technique summaries
│   └── runbooks/                 # SOC response runbooks
└── scenarios/
    ├── brute_force.py
    ├── powershell_suspicious.py
    ├── privilege_escalation.py
    └── e2e_test.py               # Full pipeline integration test
```

---

## Hardware Used

- RAM: 32 GB DDR5
- Storage: 2 TB NVMe SSD
- OS: Linux
- LLM: Ollama llama3.1:8b (4.9 GB, fully local)
