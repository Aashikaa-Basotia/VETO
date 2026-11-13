# VETO Demo Checklist

### Before demo
□ Generate evaluation report if needed (`.\.venv\Scripts\python -m evaluator.metrics`)
□ Generate benchmark report if needed (`.\.venv\Scripts\python -m evaluator.benchmark`)
□ Start downstream mock service on port 8000 (`.\.venv\Scripts\python -m mcp_servers.downstream_service`)
□ Start VETO security gateway on port 8001 (`.\.venv\Scripts\python -m gateway.gateway`)
□ Start React dashboard on port 5173 (`cd frontend && npm.cmd run dev`)
□ Verify gateway status (Operational indicator active in Sidebar)
□ Reset demo databases if needed (`.\.venv\Scripts\python reset_demo.py`)
□ Confirm dashboard loads (`http://localhost:5173/`)
□ Confirm approval request available (Check `/approvals`)
□ Confirm incoming emails page loads (`http://localhost:5173/emails`)
□ (Optional) Run email watcher cycle (`.\.venv\Scripts\python -m services.email_watcher --once`)
□ (Optional) Run safe AI email processor cycle (`.\.venv\Scripts\python -m services.email_processor --once`)

### During demo
□ Overview (Show live SQLite metrics, evaluation KPIs, and gateway architecture node pipeline)
□ Legitimate request (Show ALLOW metrics for `get_downstream_status`)
□ Request inspection (Expand a request in the Security Decisions page to show layer execution trace)
□ Approval flow (Show `REQUIRE_APPROVAL` state, click Approve, explain request hash binding)
□ Cross-service attack (Navigate to Cross-Service demo, show Gmail operation failing Calendar destination matching)
□ Unauthorized capability (Explain how restricted context overrides prompt instructions)
□ Replay attack (Highlight that a previously used Request ID is blocked securely by the `replay_detected` reason)
□ Incoming Email Review Dashboard (Navigate to `/emails`: demonstrate live summary KPI cards, filtering by classification, risk, and state)
□ Unprocessed vs. SAFE Distinction (Highlight that unprocessed emails are visually isolated in yellow/amber and NOT categorized as SAFE)
□ AI Advisory Inspection (Click an email row to inspect untrusted snippet, AI rationale, risk tier, and mandatory human review callouts)
□ Read-Only Boundary & Live OAuth Status (Emphasize that dashboard review is read-only with 0 tool execution, and real Gmail OAuth remains deferred due to Google's `invalid_grant` revocation)
□ Evaluation metrics (Show the Confusion Matrix, 36 fixtures, and 350 mutation test results)
□ Performance benchmarks (Show the Decision Path latencies, micro-benchmarks, and <0.05ms policy logic)
□ Audit trail (Show the immutable SQLite logs rendered in the timeline)

### Emergency fallback
**Downstream service failure:**
1. `Ctrl+C` the downstream python process
2. `.\.venv\Scripts\python -m mcp_servers.downstream_service`

**Gateway backend failure:** 
1. `Ctrl+C` the gateway python process
2. `.\.venv\Scripts\python -m gateway.gateway`

**Frontend failure:**
1. `Ctrl+C` the vite process
2. `npm.cmd run dev`

**State failure:**
Run the reset script: `.\.venv\Scripts\python reset_demo.py` to truncate SQLite tables for a fresh start.
