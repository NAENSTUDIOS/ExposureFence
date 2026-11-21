# ExposureFence — Release Packaging, Deployment & Operations Runbook

**Document Version:** 2.0.0-RELEASE  
**Release Target:** ExposureFence Production / Verification Candidate  
**Classification:** Enterprise Cloud Security Architecture  
**Owner:** NAENSTUDIOS  
**Compliance Standard:** CIS AWS Foundations Benchmark v3.0, NIST CSF 2.0, OWASP LLM 2025, ISO/IEC 27001  

---

## 1. Executive Summary & Package Architecture

ExposureFence is an enterprise-grade AWS Cloud Security Governance, Attack-Path Intelligence, and AI-Assisted Response Assurance Platform. It couples deterministic multi-hop graph modeling, canonical evidence provenance (RFC 8785), declarative YAML rules enforcement, cryptographic dossier sealing (Merkle root verification), and four-eye human-in-the-loop approval workflows to govern cloud remediation without human friction or autonomous runaway risks.

### Release Invariants & Guarantees
1. **Permanent Zero Out-of-Pocket Budget:** \$0.00 / ₹0.00 cloud cost policy. All local verification runs with 100% fidelity without invoking paid cloud infrastructure.
2. **Cryptographic Proof Chain:** No automated remediation execution is permitted without an immutable chain of evidence:
   $$\text{Evidence Digest} \longrightarrow \text{Declarative Rule Pass} \longrightarrow \text{State Machine Approval} \longrightarrow \text{Role Authorization} \longrightarrow \text{Ground-Truth Revalidation}$$
3. **Four-Eye RBAC Separation:** The AI Agent (`BedrockAgentCore`) is architecturally blocked from approving its own proposals. Approvals require authenticated `APPROVER` or `ADMINISTRATOR` credentials; execution requires `ADMINISTRATOR` authority.
4. **Finite Traversal Resource Guarantees:** Graph traversal algorithms incorporate deterministic hard ceilings ($K \le 50$ paths, $\le 1000$ operations) and cycle elimination to prevent algorithmic complexity denial of service.

---

## 2. Release Artifacts Manifest

| Artifact | Path | Purpose |
| :--- | :--- | :--- |
| **API Server & Routing** | `backend/server.py` | Standalone multi-threaded HTTP server hosting REST APIs and UI |
| **Evidence Ledger** | `backend/evidence/` | RFC 8785 canonical evidence collector, store, and Merkle dossiers |
| **Rules Engine** | `backend/rules/` | Declarative YAML rules compiler and deterministic evaluation engine |
| **Graph Traversal Engine** | `backend/graph/` | Bounded BFS multi-hop attack path search and IAM privilege escalation |
| **Governance & Proof Chain**| `backend/governance/` | State machine lifecycle, authorization gate, and ground-truth verifier |
| **Compliance Service** | `backend/compliance/` | Fine-grained mapping for CIS AWS v3.0 and NIST CSF 2.0 |
| **Observability Telemetry** | `backend/observability/` | Database backups, WAL checkpointing, and Prometheus-style metrics |
| **AgentCore Harness** | `agent/` | Inline-function tool dispatchers with strict parameter sanitization |
| **Security Operations Console** | `dashboard/` | Single-page responsive operations UI (12 tabs, zero CDN dependencies) |
| **Container Engine** | `Dockerfile`, `docker-compose.yml` | Multi-stage unprivileged Docker packaging with health probes |
| **Verification Suites** | `tests/offline/` | 241 offline tests covering unit, integration, and red-team attacks |

---

## 3. Pre-Deployment Verification Checklist

Before deploying or running ExposureFence in any target environment, execute the automated pre-flight verification sequence:

```bash
# 1. Activate isolated Python virtual environment
source .venv/bin/activate  # or .venv\Scripts\activate on Windows

# 2. Verify all 241 automated tests pass with 100% coverage of core invariants
python -m pytest tests/offline backend/test_database.py -v

# 3. Verify declarative rules engine and attack scenario scorecard
python -m backend.evaluate

# 4. Verify static code quality and zero hardcoded secrets
flake8 backend agent tests --max-line-length=120
bandit -r backend agent -ll -q
pip-audit
```

*Expected Verification Output:*
- Total Tests: **241 Passed (0 Failed, 0 Skipped)**
- Scorecard: **R01–R07 PASS, T01–T07 PASS (Score: 100%)**
- Flake8 / Bandit / Pip-Audit: **0 Critical Vulnerabilities**

---

## 4. Deployment Runbooks

### Option A: Production Container Deployment (Recommended)

1. **Build and start the container via Docker Compose:**
   ```bash
   docker compose up -d --build
   ```

2. **Verify container health:**
   ```bash
   docker compose ps
   docker compose logs -f exposurefence
   ```

3. **Check health probe endpoint:**
   ```bash
   curl -s http://localhost:8000/api/health | jq .
   ```

### Option B: Bare-Metal / Local Python Host

1. **Install pinned dependencies:**
   ```bash
   pip install --no-cache-dir -r requirements.txt
   ```

2. **Launch HTTP API & Console daemon:**
   ```bash
   python -m backend.server 8000
   ```

3. **Open browser:** Navigate to `http://localhost:8000` to access the Security Operations Console.

---

## 5. Configuration & Environment Variables

| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `PORT` | `8000` | TCP port for HTTP API and static dashboard |
| `EXPOSUREFENCE_DATA_MODE` | `mock` | Data source: `mock` (zero-cost offline) or `aws` (read-only live) |
| `EXPOSUREFENCE_DB_PATH` | `exposurefence.db` | Absolute path to SQLite proposal and evidence database |
| `EXPOSUREFENCE_AUDIT_PATH` | `audit.jsonl` | Absolute path to append-only cryptographic audit ledger |
| `AWS_DEFAULT_REGION` | `us-east-1` | AWS region for read-only connectors and AgentCore harness |
| `ZERO_COST_ENFORCED` | `true` | When true, strictly aborts any destructive or paid cloud mutations |

---

## 6. Operational Telemetry & Monitoring Runbook

ExposureFence exposes dedicated operational health and observability endpoints:

### Liveness & Readiness Probes (`GET /api/health`)
Returns real-time status of database access, write-ahead logging (WAL), audit log integrity, and memory footprint:
```json
{
  "status": "healthy",
  "data_mode": "mock",
  "audit_chain_valid": true,
  "database_connected": true,
  "wal_mode_enabled": true,
  "timestamp": "2026-11-21T02:15:00Z"
}
```

### Prometheus Metrics (`GET /api/metrics`)
Provides system metrics, request counters, error rates, and security proposal metrics:
```text
# HELP exposurefence_proposals_total Total proposals recorded by status
# TYPE exposurefence_proposals_total counter
exposurefence_proposals_total{status="PENDING"} 3
exposurefence_proposals_total{status="APPROVED"} 5
exposurefence_proposals_total{status="EXECUTED"} 2
exposurefence_proposals_total{status="REJECTED"} 1
exposurefence_audit_events_total 142
exposurefence_offline_tests_passing 241
exposurefence_security_score 100
```

### Database Backup & Verification Runbook
To trigger a point-in-time snapshot with SHA-256 verification:
```python
from backend.observability.backups import create_backup, verify_backup

backup_res = create_backup("exposurefence.db", backup_dir="backups")
print("Backup Manifest Created:", backup_res["manifest_path"])

verification = verify_backup(backup_res["manifest_path"])
assert verification["valid"] is True, "Backup integrity verification failed!"
```

---

## 7. Governance, Proof Chain & State Machine Lifecycle

```
       [DISCOVERED FINDING]
                │
                ▼
      [COLLECT EVIDENCE] (RFC 8785 Canonical Digest)
                │
                ▼
       [EVALUATE RULES] (Declarative YAML Engine)
                │
                ▼
       [CREATE PROPOSAL] (State: PENDING)
                │
     ┌──────────┴──────────┐
     ▼                     ▼
[REJECT PROPOSAL]    [APPROVE PROPOSAL] (State: APPROVED)
(State: REJECTED)    - Requires APPROVER or ADMIN role
                     - Verifies active session boundary
                     - Validates evidence hash match
                           │
                           ▼
                 [EXECUTE & VERIFY] (State: EXECUTED)
                 - Requires ADMINISTRATOR role
                 - Validates lifecycle state == APPROVED
                 - Independent Ground-Truth Query
                 - Drift Detection & Remediation Assertion
```

---

## 8. Rollback & Disaster Recovery Procedures

1. **Proposal Rollback:**
   - In the event of an unintended remediation, execute the inverse proposal generated during pre-flight planning.
   - All state transitions and inverse actions are captured in `audit.jsonl` with previous state snapshots.
2. **Database Restoration:**
   - Locate the most recent verified backup manifest in `backups/manifest_*.json`.
   - Verify SHA-256 integrity: `python -c "from backend.observability.backups import verify_backup; print(verify_backup('backups/manifest_XYZ.json'))"`.
   - Restore database file to active path: `cp backups/backup_*.db exposurefence.db`.
3. **Audit Ledger Verification:**
   - Execute audit chain verification tool: `python -c "from backend.audit import verify_audit_hash_chain; assert verify_audit_hash_chain(), 'Audit log compromised!'"`
