# ExposureFence — System Architecture (Amazon Bedrock AgentCore Edition)

**Project Concept:** Autonomous Cloud Security Governance with "Rules as Tests"  
**Target Platform:** Amazon Bedrock AgentCore Managed Harness  
**Enforcement Principle:** Invariant Verification Grounded in Cryptographic Evidence  

---

## 1. End-to-End Architectural Dataflow

```
User / Security Officer
       │
       ▼ (Browser: HttpOnly Cookie + CSRF Header)
[ ExposureFence Security Operations Console ]  (dashboard/index.html & app.js)
       │
       ▼ (Bound strictly to 127.0.0.1:8000 via ThreadingHTTPServer)
[ Local Python Backend Server ] (backend/server.py)
       │
       ▼ (boto3: bedrock-agentcore Converse Streaming)
[ Amazon Bedrock AgentCore Managed Harness ] (ExposureFenceHarness)
       │
       ├─► [ Amazon Bedrock Foundation Model ] (Claude 3.5 Sonnet v2)
       │
       ▼ (stream: toolUse events intercepted)
[ 12-Step Inline Tool Dispatcher ] (agent/agentcore_client.py)
       │
       ▼ (Strict 3-Tool Allowlist)
[ Server-Side Dispatcher ] (backend/dispatcher.py)
       ├── 1. read_mock_s3 ──────────► [ Fixture Hash Integrity ] (backend/integrity.py)
       ├── 2. read_mock_security_groups ──► [ SHA-256 Digest Check ] (mock_data/*.json)
       └── 3. propose_fix ───────────► [ Proposal Engine (PENDING) ] (backend/proposals.py)
                                                     │
                                                     ▼
                                     [ SQLite Database (WAL Mode) ] (exposurefence.db)
                                                     │
                                                     ▼ (Out-of-band human decision)
                                     [ Human Approval Workflow ] (backend/approvals.py)
                                                     │
                                                     ▼
                                     [ Tamper-Evident Audit Log ] (audit.jsonl)
                                       (SHA-256 Hash Chained: prev_hash -> event_hash)
```

---

## 2. Core Architectural Layers

### Layer 1: Security Operations Console (Presentation Plane)
- **Local Server (`backend/server.py`):** Standard-library `ThreadingHTTPServer` bound strictly to `127.0.0.1:8000`. Zero external CDNs, React, or Vite dependencies.
- **Authentication (`backend/auth.py`):** Single-admin Bcrypt password verification. Generates server-side HttpOnly, SameSite=Strict session cookies and cryptographic CSRF tokens.
- **Tab Views (`dashboard/index.html`):** 8 lightweight views:
  1. Executive Overview
  2. Security Scorecard (R01–R07 & T01–T07)
  3. Exposure Findings
  4. Evidence Registry
  5. Proposal Governance (Interactive Review & State Transitions)
  6. Audit Timeline (SHA-256 chained events)
  7. Offline Attack Center
  8. AgentCore Live Console (AWS status, model chat, and live test runner)

### Layer 2: AgentCore Integration & Inline Tool Handoff
- **Client (`agent/agentcore_client.py`):** Manages the 12-step Converse streaming handoff loop with Amazon Bedrock AgentCore.
- **Managed Harness (`agent/deploy.py`):** Configures `ExposureFenceHarness` with Claude 3.5 Sonnet v2, system instructions, and explicit `allowedTools`.
- **Tool Surface Restriction:** Built-in shell, code interpreter, browser, and file write tools are explicitly disabled. The tool surface is restricted to exactly three inline functions:
  1. `read_mock_s3`: Reads synthetic S3 bucket security configurations.
  2. `read_mock_security_groups`: Reads synthetic EC2 security-group ingress rules.
  3. `propose_fix`: Submits a safe remediation proposal for human review.

### Layer 3: Security Kernel & Boundary Enforcement
- **Allowlist Dispatcher (`backend/dispatcher.py`):** Rejects any tool not in `ALLOWED_TOOLS` with `ValueError("Unauthorized tool")`.
- **Fixture Integrity (`backend/integrity.py`):** Re-verifies SHA-256 digests of mock data files before reading. Any modification raises `ValueError("Fixture integrity violation")`.
- **Zero Cloud Mutation Invariant:** No cloud write tools exist in the codebase. All findings lead exclusively to `PENDING` database proposals.

### Layer 4: State Machine & Governance
- **Proposal Isolation (`backend/proposals.py`):** Proposals are inserted with hardcoded `status = "PENDING"`.
- **Out-of-Band Approvals (`backend/approvals.py`):** Transition to `APPROVED` or `REJECTED` strictly requires a valid admin session ID. Chat-based approval requests are rejected with `PermissionError`.
- **Persistence (`exposurefence.db`):** SQLite database configured in Write-Ahead Logging (`WAL`) mode with a 20.0-second busy timeout.

### Layer 5: Cryptographic Audit Trail
- **Tamper-Evident Chaining (`backend/audit.py`):** Every tool invocation and approval decision logs a record to `audit.jsonl`.
- **Hash Formula:**
  ```python
  canonical = f"{prev_hash}|{timestamp}|{event_type}|{json.dumps(details, sort_keys=True)}"
  event_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
  ```
- **Verification:** `verify_audit_hash_chain()` recalculates the entire chain from Genesis (`0000...0000`). If any past record is modified, the check returns `False`.
- **Zero Mutation Verification:** `verify_zero_mutations()` scans all historical event payloads to ensure zero mutation markers exist.

---

## 3. Rules as Tests Matrix (R01–R07 & T01–T07)

| Rule ID | Rule Policy | Enforcement Layer | Verifying Attack Test | Expected Outcome |
| :---: | :--- | :--- | :---: | :--- |
| **R01** | Mock data only | Application Boundary | `T01` | Shell/secrets blocked; fixture SHA-256 intact. |
| **R02** | No cloud mutations | Tool Surface | `T02` | Mutation tools blocked; mutation count = 0. |
| **R03** | Three tool limit | Server Dispatcher | `T03` | IAM and unknown tools raise `Unauthorized tool`. |
| **R04** | Proposal only | Proposal Engine | `T04` | Egress tools blocked; proposals remain `PENDING`. |
| **R05** | Separate human approval | Authentication Gate | `T05` | Conversational approval fails; session token required. |
| **R06** | Untrusted fixture content | Validation Engine | `T06` | Injected prompt in metadata treated as passive string. |
| **R07** | Evidence required | Scoring Engine | `T07` | Unregistered evidence ID causes finding rejection. |
