# VETO: Verified Execution & Trust Orchestration

Deterministic runtime security gateway and empirical adversarial evaluation platform for AI agents.

VETO intercepts, validates, and arbitrates tool invocations between AI agents (via the Model Context Protocol) and downstream services (internal APIs, Gmail, and Google Calendar) before execution occurs.

---

## Architecture Overview

```
[ Adversary / User Prompt ]
            │
            ▼
   [ AI Agent Loop ]
            │
            ▼
    [ MCP Client ] ── (Signs payload with HMAC-SHA256)
            │
            ▼
┌────────────────────────────────────────────────────────┐
│                 VETO SECURITY GATEWAY                  │
│                                                        │
│  1. Cryptographic Provenance (HMAC-SHA256)             │
│  2. Replay Protection (Single-use request_id)          │
│  3. Capability Policy (Allowlist matrix)               │
│  4. Destination Trust (1:1 capability-to-host binding) │
│  5. Risk Classification (LOW, MEDIUM, HIGH, CRITICAL)  │
│  6. Context Security (Execution mode checks)           │
│  7. Human Approval Machine (Cryptographic token bound) │
└───────────────────────────┬────────────────────────────┘
                            │
              ┌─────────────┴─────────────┐
              ▼                           ▼
     [ Downstream Services ]      [ SQLite Audit Log ]
```

---

## Core Security Layers

1. **Cryptographic Provenance**: Every tool request is signed using HMAC-SHA256. Unsigned or modified payloads are rejected immediately.
2. **Replay Defense**: Enforces single-use request IDs recorded in SQLite for all state-changing mutations.
3. **Capability Policies**: Checks if the agent identifier is explicitly authorized to execute the requested operation.
4. **Destination Trust Binding**: Validates destination hostnames to prevent SSRF and cross-service manipulation.
5. **Risk Classification**: Categorizes actions by risk tier; high-consequence operations require human approval.
6. **Context Enforcement**: Blocks sensitive operations when operating in restricted execution modes.
7. **Human-in-the-Loop Approval**: Generates signed approval challenges for critical mutations.
8. **Immutable Audit Trail**: Logs every decision, hash, and latency metric to an immutable SQLite database.

---

## Directory Layout

```
VETO/
├── agent/            # Agent runtime and MCP client implementations
├── attacks/          # Adversarial test fixtures and mutation runner
├── backend/          # Security gateway, policy engines, and services
│   ├── approval/     # Human approval verification engine
│   ├── audit/        # SQLite audit logger
│   ├── context/      # Context security evaluator
│   ├── evaluator/    # Metrics and latency benchmarks
│   ├── gateway/      # FastAPI gateway application
│   ├── mcp_servers/  # Mock downstream service and MCP test server
│   ├── policy/       # Capability allowlist engine
│   ├── provenance/   # HMAC signature verifier
│   ├── replay/       # SQLite replay engine
│   ├── risk/         # Risk evaluator and destination validator
│   └── services/     # Gmail and Google Calendar service adapters
├── docs/             # Architecture documentation and reports
├── frontend/         # React + TypeScript + Vite security dashboard
├── scripts/          # OAuth helper and reset utilities
└── tests/            # Unit, integration, and security test batteries
```

---

## Quickstart

### Prerequisites
- Python 3.11+
- Node.js 18+ and npm

### 1. Environment Setup

```bash
# Clone the repository
git clone https://github.com/Aashikaa-Basotia/VETO.git
cd VETO

# Setup Python environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# Setup Frontend
cd frontend
npm install
cd ..
```

### 2. Running Services

**Terminal 1 — Mock Downstream Service (:8000)**
```bash
python -m backend.mcp_servers.downstream_service
```

**Terminal 2 — VETO Gateway (:8001)**
```bash
python -m backend.gateway.gateway
```

**Terminal 3 — Frontend Dashboard (:5173)**
```bash
cd frontend
npm run dev
```

---

## Testing & Benchmarks

```bash
# Run pytest test battery
pytest -q

# Run canonical adversarial attacks
python -m attacks.runner

# Run synthetic payload mutation tests
python -m attacks.mutation_runner

# Run latency and throughput benchmarks
python -m backend.evaluator.benchmark
```
