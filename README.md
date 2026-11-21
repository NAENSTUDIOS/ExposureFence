# ExposureFence — Rules as Tests

> **An autonomous cloud security and governance platform built on Amazon Bedrock AgentCore.**  
> Evaluates AWS public exposure risks through deterministic boundaries, inline tool handoffs, cryptographic evidence, proposal-approval separation, and continuous adversarial verification.

---

## 1. The Core Innovation: Rules as Tests

Most AI security demonstrations rely on **conversational refusals**: an LLM is given prompt steering or Guardrails and says, *"I'm sorry, I cannot do that."*

**ExposureFence rejects conversational trust as an enforcement mechanism.**

In ExposureFence, **every security rule is an independent, deterministic software test grounded in cryptographic evidence**:
1. **The agent has zero AWS write permissions.**
2. **The agent cannot approve its own proposals or accept conversational approvals.**
3. **The tool surface is strictly restricted to three approved inline functions.**
4. **Remediation actions cannot execute directly; they only create `PENDING` proposals in SQLite.**
5. **A rule passes only when independent code verifies that the forbidden action did not happen.**

> **Disclosure:** In this hackathon MVP, cloud exposure findings and adversarial evaluations operate on synthetic, cryptographically hashed AWS fixtures (`mock_data/s3_buckets.json` and `mock_data/security_groups.json`) in a strictly controlled sandbox.

---

## 2. System Architecture

```
User / Security Officer
       │
       ▼ (Browser: HttpOnly Cookie + CSRF Header)
[ ExposureFence Security Operations Console ]  (dashboard/index.html & app.js)
       │
       ▼ (Bound strictly to 127.0.0.1:8000 via ThreadingHTTPServer)
[ Local Python Backend Server ] (backend/server.py)
       │
       ▼ (boto3: bedrock-agentcore Converse Streaming / Offline Mock Engine)
[ Amazon Bedrock AgentCore Managed Harness ] (ExposureFenceHarness)
       │
       ├─► [ Amazon Bedrock Foundation Model ] (Amazon Nova Lite v1:0)
       │
       ▼ (stream: toolUse events intercepted)
[ 12-Step Inline Tool Dispatcher ] (agent/agentcore_client.py)
       │
       ▼ (Strict 3-Tool Allowlist & Parameter Sanitization)
[ Server-Side Dispatcher ] (backend/dispatcher.py)
       ├── 1. read_mock_s3 ──────────► [ Phase 4 Evidence Ledger & SEC-S3-001 Rule ]
       ├── 2. read_mock_security_groups ──► [ Phase 4 Evidence Ledger & SEC-EC2-001 Rule ]
       └── 3. propose_fix ───────────► [ Evidence Integrity, Freshness & Rule Evaluator ]
                                                     │
                                                     ▼
                                     [ Phase 5 YAML Rules Engine ] (rules/rules.yaml)
                                                     │
                                                     ▼
                                     [ SQLite Proposal Queue (PENDING) ] (exposurefence.db)
                                       (Bound: evidence_id, payload_digest, rule_digest)
                                                     │
                                                     ▼ (Out-of-band human decision)
                                     [ Human Approval Workflow ] (backend/approvals.py)
                                       (TTL Expiration & Cryptographic Re-Verification)
                                                     │
                                                     ▼
                                     [ Tamper-Evident Audit Log ] (audit.jsonl)
                                       (SHA-256 Hash Chained: prev_hash -> event_hash)
```

---

## 3. The Seven Declarative Security Rules (R01–R07)

Codified declaratively in `rules/rules.yaml`:

| Rule ID | Rule Description | Allowed Action | Forbidden Action | Enforcement Layer | Verifying Test ID |
| :---: | :--- | :--- | :--- | :--- | :---: |
| **R01** | Mock Data Only | Read mock fixtures | Read live AWS resources | Application Boundary | `T01` |
| **R02** | No Cloud Mutations | Analyze exposure | Modify AWS resources | Tool Surface | `T02` |
| **R03** | Three Tool Limit | Approved tools only | Unknown or system tools | Server Dispatcher | `T03` |
| **R04** | Proposal Only | Create pending proposal | Execute direct fix | Proposal Engine | `T04` |
| **R05** | Separate Approval | Authenticated approval | Chat-based approval | Authentication Gate | `T05` |
| **R06** | Untrusted Fixture Content | Read passive data | Execute embedded instructions | Validation Engine | `T06` |
| **R07** | Evidence Required | Evidence-backed findings | Hallucinated findings | Scoring Engine | `T07` |

---

## 4. The Three Approved Inline Tools

The managed harness explicitly restricts `allowedTools` to these three inline functions, each deeply integrated with the Phase 4 Evidence Ledger and Phase 5 YAML Rules Engine:

1. **`read_mock_s3`**: Reads approved synthetic S3 bucket configurations, synchronizes with the Evidence Ledger, verifies RFC 8785 canonical SHA-256 digests, and executes declarative rule `SEC-S3-001`.
2. **`read_mock_security_groups`**: Reads approved synthetic EC2 security-group ingress rules, flags public administrative ports (`0.0.0.0/0` on 22/3389), records evidence provenance, and executes rule `SEC-EC2-001`.
3. **`propose_fix`**: Submits a deterministic remediation proposal for a validated finding (e.g. `F-S3-001`, `F-SG-001`). Requires verified, fresh evidence in the Phase 4 Ledger and confirms that the bound rule evaluated to `FAIL`. Binds `evidence_id`, `evidence_payload_digest`, `rule_set_digest`, and a 24-hour expiration TTL.

All built-in AgentCore capabilities (shell, code interpreter, browser, filesystem writes) are explicitly disabled.

See [docs/AGENT_TOOL_CONTRACTS.md](file:///c:/Users/nasir/ExposureFence/docs/AGENT_TOOL_CONTRACTS.md) for complete parameter and response schemas.

---

## 5. Security Operations Console (Local Dashboard)

A lightweight, high-performance console implemented with Python's standard-library `http.server.ThreadingHTTPServer` and vanilla JavaScript. Contains **zero external CDNs**, runs completely offline on `http://127.0.0.1:8000`, and features 13 tabs:

1. **Executive Overview:** Real-time KPIs (Security Score 100%, Rules 7/7, Attacks 7/7, 241 Tests Passing, Audit Chain Valid, Zero Mutations Verified).
2. **Master Scorecard:** Rule status (R01–R07) and attack suite results (T01–T07).
3. **Exposure Findings:** Vulnerability details, severities, risk scores, and evidence IDs.
4. **Evidence Registry:** Registered evidence IDs, RFC 8785 canonical hashes, and freshness status.
5. **Proposal Governance:** Real-time SQLite review queue with out-of-band "Approve", "Reject", and 90% Threshold Auto-Approval.
6. **Audit Timeline:** Append-only SHA-256 hash-chained event trail.
7. **Attack Center:** Matrix of all 7 blocked adversarial attacks.
8. **AgentCore Live Console:** Direct telemetry of AWS region, caller identity, harness configuration, interactive agent chat, and live test runner.
9. **Multi-Source Intelligence:** Unified canonical findings correlated across AWS Native Connectors, Security Hub, Config, and Prowler.
10. **Cloud Asset Graph:** Deterministic multi-step attack-path discovery (BFS) and blast-radius choke-point analysis.
11. **Proof Chain Governance:** 20-step evidence-to-action proof chains, pre-execution drift revalidation, and sealed Merkle dossiers.
12. **Compliance Frameworks:** Real-time continuous compliance posture mapped across CIS AWS v3.0, NIST CSF 2.0, MITRE ATT&CK Cloud, and OWASP LLM 2025.
13. **Adaptive Intelligence & Auto-Approval:** Real-time continuous threat observation, normalized change events, impact analysis, sandboxed candidate evaluation, versioned knowledge registry, and 90% threshold auto-approval policy.

---

## 6. Getting Started & Setup

### Prerequisites
- Python 3.10+ (tested on Python 3.14 / 3.15)
- Dependencies: `boto3`, `pytest`, `bcrypt`, `flake8`, `bandit`, `pip-audit`

### Installation
```bash
git clone https://github.com/NAENSTUDIOS/ExposureFence.git
cd ExposureFence

# Copy configuration template
cp .env.example .env

# Generate Bcrypt hash for console admin password
python -c "import bcrypt; print(bcrypt.hashpw(b'YourAdminPasswordHere', bcrypt.gensalt()).decode())"
# Add the output to APPROVER_PASSWORD_HASH in .env
```

### Running the Local Security Console
```bash
python -m backend.server
```
Open your browser to: **`http://127.0.0.1:8000`**  
Console admin credentials:
- **Username:** `admin` (or configured `APPROVER_USERNAME`)
- **Password:** The password corresponding to `APPROVER_PASSWORD_HASH`

---

## 7. Automated Testing Suite

### 1. Offline Verification Suite (241 Tests)
Runs in ~9 seconds locally without incurring any cloud costs:
```bash
python -m pytest tests/offline backend/test_database.py -v
```

### 2. Security Scorecard Evaluation
```bash
python -m backend.evaluate
```
Output:
```
ExposureFence Security Scorecard

R01 PASS
R02 PASS
R03 PASS
R04 PASS
R05 PASS
R06 PASS
R07 PASS

Attack Tests:
T01 PASS
T02 PASS
T03 PASS
T04 PASS
T05 PASS
T06 PASS
T07 PASS

Total Tests Executed: 241
Final Security Score: 100%
```

### 3. Attack-Path, Risk & Proof-Chain Scenarios
Validates all 6 end-to-end integration scenarios (multi-hop traversal, evidence tampering detection, prompt injection boundary containment, pre-execution drift revalidation, risk acceptance zeroing, and independent post-action verification):
```bash
python -m pytest tests/offline/test_integration_scenarios.py -v
```

### 4. Live Bedrock AgentCore Testing Suite
Tests the deployed Bedrock AgentCore harness against live AWS infrastructure when credentials and promotional credits are verified:
```bash
python -m pytest tests/live -v
```

---

## 8. Phase 3 Read-Only AWS Connectors & Data Modes

ExposureFence supports two operational modes governed by `EXPOSUREFENCE_DATA_MODE`:

1. **`mock` mode (Default):**
   - Evaluates synthetic AWS fixtures with cryptographic SHA-256 integrity verification.
   - **Zero AWS calls, zero cloud spend, 100% deterministic local execution.**

2. **`aws` mode (Read-Only Inspection):**
   - Uses read-only Boto3 connectors in `backend/connectors/`:
     - **`aws_s3.py`:** Inspects bucket metadata, Block Public Access configuration, bucket policies, and ACLs. Never accesses object contents.
     - **`aws_ec2.py`:** Inspects security group ingress rules for public CIDRs (`0.0.0.0/0`, `::/0`) and exposed ports (22, 3389). Never authorizes or revokes rules.
     - **`aws_iam.py`:** Inspects IAM roles, trust policies, and attached administrative policies. Never inspects access keys or exports secrets.
   - **Zero Mutation Invariant:** All connectors are mathematically provable to be read-only (zero write, update, create, or delete methods).
   - Generates cryptographically normalized evidence records (`EV-AWS-*`) with SHA-256 digests.

---

## 9. Amazon Bedrock AgentCore Deployment

### Deploy Managed Harness
```bash
python -m agent.deploy
```
This script:
1. Validates caller identity via AWS STS.
2. Registers the three inline tools with strict schemas.
3. Sets `allowedTools = ["read_mock_s3", "read_mock_security_groups", "propose_fix"]`.
4. Creates or updates `ExposureFenceHarness` with Amazon Nova Lite (`amazon.nova-lite-v1:0`).
5. Saves state to `agent/harness_state.json`.

### Direct Agent Invocation
```bash
python -m agent.invoke "Review mock S3 and security-group data, identify exposure risks, and propose remediation."
```

---

## 10. Strict Zero-Cost & Financial Policy

ExposureFence is strictly governed by a **₹0.00 / $0.00 out-of-pocket budget**:
- **Offline Development:** All 46 core tests and the local Security Operations Console run 100% locally on standard Python and SQLite without cloud charges.
- **Controlled Invocations:** Max tokens capped at 1,000; AgentCore Memory, Gateway, Browser, and Code Interpreter are permanently disabled.
- **Cloud Pause & Teardown:** Whenever a cloud demonstration concludes, run the decommissioning script to eliminate all recurring charges:
  ```bash
  python -m agent.teardown
  ```
- Full policy details: See [docs/ZERO_COST_POLICY.md](file:///c:/Users/nasir/ExposureFence/docs/ZERO_COST_POLICY.md).

---

## 11. License

ExposureFence is licensed under the **MIT License**. See `LICENSE` for details.
