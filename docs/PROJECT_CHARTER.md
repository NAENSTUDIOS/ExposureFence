# EXPOSUREFENCE — CAREER-FIRST PROJECT CHARTER

## 1. Project Identity

**ExposureFence** is my flagship, long-term AWS Cloud Security Engineering portfolio project.

It is **NOT** a temporary hackathon throwaway application.

The AWS Agents, Your Rules hackathon is one milestone in the development of this larger enterprise security platform.

The project is architected and built to remain a durable asset for:
- **AWS Cloud Security Engineering Internships**
- **Cloud Infrastructure & Architecture Internships**
- **Security Engineering & DevSecOps Technical Interviews**
- **Adversarial AI Defense & LLM Boundary Demonstrations**
- **Open-source Cloud Governance Tooling**
- **Production-grade Cloud Security Platform Development**

---

## 2. Primary Mission

Build a complete, end-to-end AWS Cloud Security Governance Platform.

The platform connects and integrates:

```
[ Security Operations Dashboard ] (Lightweight local console, zero external CDNs)
       │
       ▼
[ REST API & Session Gate ] (ThreadingHTTPServer, HttpOnly cookies, CSRF protection)
       │
       ▼
[ Read-Only AWS Connectors ] (S3, EC2, IAM with zero-mutation invariant)
       │
       ▼
[ Evidence Engine ] (Cryptographic SHA-256 verification & provenance records)
       │
       ▼
[ YAML Rules Engine ] (Declarative rules codified as deterministic tests)
       │
       ▼
[ Amazon Bedrock ] (Nova Lite / Claude 3.5 Haiku ConverseStream foundation models)
       │
       ▼
[ Amazon Bedrock AgentCore ] (Managed harness orchestration & session state)
       │
       ▼
[ Three Approved Inline Tools ] (read_mock_s3, read_mock_security_groups, propose_fix)
       │
       ▼
[ Security Dispatcher ] (Strict tool allowlisting & parameter sanitization)
       │
       ▼
[ SQLite Proposal Queue ] (Deterministic remediation suggestions in PENDING state)
       │
       ▼
[ Authenticated Human Approval ] (Out-of-band operator session gate; no chat approvals)
       │
       ▼
[ Tamper-Evident Audit Log ] (Append-only SHA-256 hash chain: prev_hash -> event_hash)
```

---

## 3. Master Platform Evolution Roadmap (Groups A–N)

| Feature Group | Description | Status |
| :---: | :--- | :---: |
| **Group A** | Multi-Source Security Intelligence (Security Hub, Config, Prowler, Native Connectors) | **COMPLETE** |
| **Group B** | Cloud Asset Graph & Deterministic Attack-Path Engine (BFS, IAM Privilege Analyzer) | **COMPLETE** |
| **Group C** | Contextual Risk Engine & Risk Acceptance Registry (RiskPolicyV1 & V2, Expirations) | **COMPLETE** |
| **Group D** | Declarative YAML Rules Engine (Rules as Tests, RFC 8785 Hashing) | **COMPLETE** |
| **Group E** | Evidence-to-Action Proof Chains & 14-State Machine (Drift Revalidation, Rollback Plans) | **COMPLETE** |
| **Group F** | Amazon Bedrock AgentCore Integration (ConverseStream, 3 Inline Tools, Zero-Cost Safe) | **COMPLETE** |
| **Group G** | Security Dispatcher & Boundary Hardening (3-Tool Limit, Parameter Sanitization) | **COMPLETE** |
| **Group H** | Cryptographic Dossier Assembly & Tamper-Evident Audit Ledger (SHA-256 Merkle Seal) | **COMPLETE** |
| **Group I** | Adversarial Verification Suite (T01–T07 Invariants, Boundary Containment) | **COMPLETE** |
| **Group J** | Role-Based Access Control (RBAC: Investigator, Approver, Auditor, Admin) | **COMPLETE** |
| **Group K** | Automated DevSecOps Pipeline & Supply-Chain Security (Flake8, Bandit, Pip-Audit) | **COMPLETE** |
| **Group L** | Multi-Framework Compliance Matrix (CIS AWS v3.0, NIST CSF 2.0, MITRE, OWASP LLM) | **COMPLETE** |
| **Group M** | Enterprise Security Operations Console (13 Responsive Tabs, Zero External CDNs) | **COMPLETE** |
| **Group N** | Production Observability & Health Telemetry (/api/health, /api/metrics, Backups) | **COMPLETE** |

*All 14 Feature Groups and 241 automated tests are verified 100% passing without cloud dependencies.*

---

## 4. Three Development Objectives

### Objective A — Complete the Product
Build a unified, functional platform where dashboard, API, connectors, evidence, rules, AI agent, approvals, and audit trail operate seamlessly together.

### Objective B — Hackathon Release
Deliver a robust, verified milestone demonstrating:
- Defined security inspection and governance workflow.
- Amazon Bedrock AgentCore managed harness with 3 approved inline tools.
- Layered security boundaries (zero cloud mutations, no self-approvals).
- Live adversarial attack tests (T01–T07) with independent invariant verification.
- Cryptographically verified evidence and tamper-evident audit logs.

### Objective C — Career Portfolio
Maintain rigorous professional engineering standards:
- Modular, well-tested Python codebase (100% test pass rate).
- Production-grade AWS architecture diagrams and threat models.
- Least-privilege IAM policies and financial safety guardrails.
- Documented trade-offs, limitations, and future roadmap.
- Comprehensive technical presentation suitable for senior AWS security evaluators.

---

## 5. Financial & Cost Policy

- **Personal Budget Limit:** **₹0.00 / $0.00 out-of-pocket (STRICT ZERO-TOLERANCE)**.
- **Default Mode:** Local development using cryptographically verified synthetic fixtures (`mock_data/*.json`).
- **Cloud Usage:** Permitted only when verifiable promotional credits are confirmed in the AWS Billing Console.
- **Decommissioning:** All cloud resources must be torn down immediately after live demonstrations via `agent/teardown.py`.
- **Reproducibility:** Deployment configurations, state files, and test fixtures are permanently preserved in Git.

---

## 6. Engineering & Governance Rules

1. **Preserve Working Code:** Never overwrite or break verified functionality.
2. **Never Fabricate:** Never fake AWS calls, test results, evidence hashes, or credit availability.
3. **Strict Separation:** Always clearly distinguish between offline mock findings and live AWS data.
4. **Zero Cloud Mutation Invariant:** The AI agent and connectors must never possess write, update, or delete permissions in AWS.
5. **Separation of Duties:** The agent cannot approve its own remediation proposals; state transitions strictly require authenticated human action.
6. **Transparent Reporting:** Report technical blockers, credit limitations, and security concerns with complete honesty.
