# VETO Architecture

## Core principle
Access to a tool does not imply unrestricted authority to use it. VETO acts as a hard boundary separating AI intent from execution.

## Architecture Pipeline

```text
User
 ↓
AI Agent
 ↓
MCP
 ↓
VETO Gateway
 ├── Provenance (HMAC verification)
 ├── Replay (Idempotency and reuse prevention)
 ├── Capability (Policy-driven endpoint restrictions)
 ├── Destination (Cross-service destination validation)
 ├── Risk (Operation-based risk assessment)
 ├── Context (Execution environment evaluation)
 ├── Approval (Human-in-the-loop authorization)
 └── Audit (Immutable operation logging)
 ↓
Controlled Adapter (Safe external integration bindings)
 ↓
External / Mock Service (Gmail, Google Calendar, Downstream)
```

## Frontend

```text
React Dashboard
       ↓
VETO API
```

**Security Notice:** The React frontend acts entirely as a visualization and observability layer. It is not a security authority. It cannot bypass gateway components, sign cryptographic payloads, or authorize operations without backend resolution. Replay tokens, HMAC secrets, and downstream credentials are not exposed to the browser.
