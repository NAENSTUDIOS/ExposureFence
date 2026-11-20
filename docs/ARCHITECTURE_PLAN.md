# ExposureFence — Master Architecture & Dependency-Aware Implementation Plan

**Classification:** Architectural Blueprint & Engineering Specification  
**Version:** 3.0.0  
**Target:** Integrated AWS Cloud Security Governance, Attack-Path Intelligence & Autonomous Response Assurance Platform  

---

## 1. Target System Architecture

```
+───────────────────────────────────────────────────────────────────────────────────────────────────+
|                                1. MULTI-SOURCE INTELLIGENCE INGESTION                             |
|                                                                                                   |
|  AWS S3 Connector   AWS EC2 Connector   AWS IAM Connector   Security Hub   AWS Config   Prowler   |
|         │                  │                   │                 │             │           │      |
|         ▼                  ▼                   ▼                 ▼             ▼           ▼      |
|  [ S3 Adapter ]     [ EC2 Adapter ]     [ IAM Adapter ]     [ ASFF Adapter] [Config Adp] [Prowler]|
|         └──────────────────┬───────────────────┴─────────────────┴─────────────┴───────────┘      |
|                            ▼                                                                      |
|             [ Canonical Finding Normalization Engine ] (backend/intelligence/)                    |
|             - Severity mapping: CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL                        |
|             - Deduplication & Cross-Source Correlation                                            |
|             - Lifecycle: NEW, ACTIVE, SUPPRESSED, RESOLVED, REOPENED                              |
|             - Asset Inventory Registry (Account, Region, Resource, Config Hash, Drift Detection)  |
+────────────────────────────────────────────┬──────────────────────────────────────────────────────+
                                             │
                                             ▼
+───────────────────────────────────────────────────────────────────────────────────────────────────+
|                               2. CLOUD ASSET GRAPH & ATTACK-PATH ENGINE                           |
|                                                                                                   |
|  [ Directed Resource Graph ] (backend/graph/)                                                     |
|  - Nodes: Account, VPC, Subnet, Security Group, EC2 Instance, IAM Role, Policy, S3 Bucket, Target |
|  - Edges: MemberOf, NetworkExposed, RouteTo, AssociatedRole, GrantsPrivilege, AssumesRole, Access |
|  - Edge Evidence Statuses: CONFIRMED, INFERRED, UNKNOWN, MISSING_EVIDENCE                         |
|                                                                                                   |
|  [ IAM Privilege Escalation Analyzer ]                                                            |
|  - Dangerous combos: PassRole + RunInstances, CreatePolicyVersion, AssumeRole wildcard           |
|                                                                                                   |
|  [ Multi-Step Attack-Path Discovery ]                                                             |
|  - BFS/Dijkstra search: Public CIDR -> SG Ingress -> Workload -> IAM Escalation -> Sensitive Data|
|                                                                                                   |
|  [ Contextual Blast-Radius & Choke-Point Analysis ]                                               |
|  - Impacted downstream asset set, cumulative sensitivity score, single-point mitigation choke-pts|
+────────────────────────────────────────────┬──────────────────────────────────────────────────────+
                                             │
                                             ▼
+───────────────────────────────────────────────────────────────────────────────────────────────────+
|                               3. CONTEXTUAL RISK ENGINE                                           |
|                                                                                                   |
|  [ Deterministic Risk Calculation ] (backend/risk/)                                               |
|  - Factors: Asset Criticality * Internet Exposure * Reachability * IAM Privilege * Attack Path    |
|             * Evidence Integrity (1.0 or 0.0) * Freshness Decay                                   |
|  - Versioned Scoring Policies (v1.0.0, v2.0.0)                                                    |
|  - Explainable score component breakdown (Exposure, Privilege, Reachability, Criticality)         |
|  - Risk Acceptance Lifecycle: Business justification, approver ID, expiration timestamp           |
+────────────────────────────────────────────┬──────────────────────────────────────────────────────+
                                             │
                                             ▼
+───────────────────────────────────────────────────────────────────────────────────────────────────+
|                               4. EVIDENCE & RULES GOVERNANCE                                      |
|                                                                                                   |
|  [ Phase 4 Evidence Ledger ]                                                                      |
|  - RFC 8785 JSON Canonicalization, SHA-256 Ledger, Immutability DB Triggers, W3C PROV-O Export    |
|                                                                                                   |
|  [ Phase 5 Declarative YAML Rules Engine ]                                                        |
|  - SEC-S3-001, SEC-EC2-001, System Rules R01–R07 ("Rules as Tests")                              |
|                                                                                                   |
|  [ Compliance Framework Mapping Engine ] (backend/compliance/)                                    |
|  - CIS AWS Benchmark v3.0, NIST CSF 2.0, MITRE ATT&CK Cloud, AWS Well-Architected, OWASP LLM 2025  |
+────────────────────────────────────────────┬──────────────────────────────────────────────────────+
                                             │
                                             ▼
+───────────────────────────────────────────────────────────────────────────────────────────────────+
|                               5. AI SECURITY CONTROL PLANE                                        |
|                                                                                                   |
|  [ Amazon Bedrock AgentCore Orchestration ] (agent/agentcore_client.py)                           |
|  - Managed Harness: ExposureFenceHarness (Amazon Nova Lite v1:0)                                   |
|  - Strict 3-Tool Allowlist (read_mock_s3, read_mock_security_groups, propose_fix)                 |
|  - Safety Boundaries: Max input 4k, Max output 8k, Max 10 tool calls, Max 5 turns                 |
|  - Output Secret Scanning (redacts AKIA*, Bearer tokens, cookies)                                 |
|  - Prompt-Injection Defenses: External data treated strictly as passive JSON                      |
+────────────────────────────────────────────┬──────────────────────────────────────────────────────+
                                             │
                                             ▼
+───────────────────────────────────────────────────────────────────────────────────────────────────+
|                               6. EVIDENCE-TO-ACTION PROOF CHAIN & GOVERNANCE                      |
|                                                                                                   |
|  [ 20-Step Proof Chain Orchestrator ] (backend/governance/)                                       |
|  - Immutable Proposal State Machine:                                                              |
|    DRAFT -> PENDING -> APPROVED | REJECTED | EXPIRED | REVOKED | INVALIDATED                      |
|    -> READY_FOR_EXECUTION -> EXECUTING -> EXECUTED | EXECUTION_FAILED                             |
|    -> VERIFICATION_PENDING -> VERIFIED | VERIFICATION_FAILED                                      |
|  - Out-of-band Human Authorization: Role-Based (APPROVER or ADMIN only), CSRF protected           |
|  - Cryptographic Binding: finding_id, evidence_id, payload_digest, rule_digest, plan_digest, TTL   |
|  - Pre-Execution Revalidation: Mismatch or drift immediately invalidates approval                |
|  - Simulated Execution Gate: Zero AWS mutation invariant                                          |
|  - Independent Post-Action Verification: Re-checks ground truth evidence before marking VERIFIED   |
|  - Signed Evidence Dossier: Exportable tamper-evident investigation package                        |
+────────────────────────────────────────────┬──────────────────────────────────────────────────────+
                                             │
                                             ▼
+───────────────────────────────────────────────────────────────────────────────────────────────────+
|                               7. RBAC, OBSERVABILITY & PRODUCTION CONSOLE                         |
|                                                                                                   |
|  [ RBAC & Session Security ] (backend/rbac/)                                                      |
|  - Roles: INVESTIGATOR, APPROVER, AUDITOR, ADMINISTRATOR                                          |
|                                                                                                   |
|  [ Observability & Operational Resilience ] (backend/observability/)                              |
|  - Structured JSON Logging, Correlation IDs, /api/health, /api/metrics, Backup/Restore scripts    |
|                                                                                                   |
|  [ Security Operations Console ] (dashboard/)                                                     |
|  - 12 Responsive Tabs, Local Vanilla JS & CSS, Zero External CDNs, Bound to 127.0.0.1:8000         |
|                                                                                                   |
|  [ DevSecOps & Supply-Chain Security ] (.github/workflows/security-ci.yml)                        |
|  - Automated Test Gates, SAST, Pip-audit, Secret Scanning, Pinned Dependencies                     |
+───────────────────────────────────────────────────────────────────────────────────────────────────+
```

---

## 2. Package & Module Directory Structure

```
backend/
├── intelligence/
│   ├── __init__.py
│   ├── models.py              # CanonicalFinding, AssetRecord, Lifecycle enums
│   ├── normalization.py       # Severity, ARN, and timestamp normalizer
│   ├── s3_adapter.py          # Native S3 findings adapter
│   ├── ec2_adapter.py         # Native EC2 SG findings adapter
│   ├── iam_adapter.py         # Native IAM findings adapter
│   ├── securityhub_adapter.py # AWS Security Hub ASFF adapter
│   ├── config_adapter.py      # AWS Config compliance adapter
│   ├── prowler_adapter.py     # Prowler JSON adapter
│   ├── correlation.py         # Deduplication & cross-source correlation
│   ├── lifecycle.py           # Finding lifecycle state manager (suppression, reopen)
│   └── inventory.py           # SQLite Asset Inventory & drift detector
│
├── graph/
│   ├── __init__.py
│   ├── models.py              # Node, Edge, RelationshipStatus, Graph models
│   ├── engine.py              # In-memory & SQLite directed graph engine
│   ├── iam_analyzer.py        # Privilege escalation & dangerous combo detector
│   ├── attack_paths.py        # BFS/Dijkstra multi-step attack chain discoverer
│   ├── blast_radius.py        # Downstream reachability & choke-point calculator
│   └── visualizer.py          # Cytoscape/JSON graph export for dashboard
│
├── risk/
│   ├── __init__.py
│   ├── models.py              # RiskScore, ComponentBreakdown, RiskAcceptance
│   ├── engine.py              # Multi-factor deterministic contextual risk calculator
│   ├── policies.py            # Versioned scoring policies (v1.0.0, v2.0.0)
│   └── acceptance.py          # Risk acceptance registry with TTL & revocation
│
├── governance/
│   ├── __init__.py
│   ├── models.py              # ProposalState, ProofChainRecord, RemediationPlan
│   ├── state_machine.py       # 14-state proposal lifecycle manager
│   ├── proof_chain.py         # 20-step evidence-to-action proof chain service
│   ├── rollback.py            # Rollback plan generator & digest binder
│   ├── verifier.py            # Independent post-action verification engine
│   └── dossier.py             # Cryptographic evidence dossier generator
│
├── rbac/
│   ├── __init__.py
│   ├── models.py              # Role enum (INVESTIGATOR, APPROVER, AUDITOR, ADMIN)
│   ├── permissions.py         # Role-to-endpoint permissions matrix
│   └── service.py             # User & role manager, session assignment
│
├── compliance/
│   ├── __init__.py
│   ├── models.py              # ComplianceFramework, ControlMapping, CoverageReport
│   ├── mappings.py            # CIS AWS, NIST CSF 2.0, MITRE ATT&CK, OWASP LLM 2025
│   └── service.py             # Real-time compliance coverage calculator
│
└── observability/
    ├── __init__.py
    ├── logger.py              # Structured JSON logging with correlation IDs
    ├── metrics.py             # Performance & security KPI metrics registry
    ├── health.py              # Health check & readiness probes
    └── backup.py              # Database & audit ledger snapshot/restore utility
```

---

## 3. Database Migration Strategy (Additive & Reversible)

All database extensions will execute additively within `backend/database.py` via `initialize_db()`:

1. **`canonical_findings`**:
   - `finding_id` TEXT PRIMARY KEY
   - `source_id` TEXT, `source_type` TEXT, `raw_finding_hash` TEXT
   - `resource_arn` TEXT, `account_id` TEXT, `region` TEXT, `service` TEXT
   - `title` TEXT, `description` TEXT, `severity` TEXT, `status` TEXT
   - `first_seen` TEXT, `last_seen` TEXT, `suppression_reason` TEXT, `suppressed_until` TEXT
   - `evidence_id` TEXT, `correlation_id` TEXT

2. **`cloud_asset_inventory`**:
   - `resource_arn` TEXT PRIMARY KEY
   - `account_id` TEXT, `region` TEXT, `service` TEXT, `resource_type` TEXT
   - `resource_id` TEXT, `tags_json` TEXT, `configuration_digest` TEXT
   - `last_scanned` TEXT, `is_active` INTEGER, `drift_detected` INTEGER

3. **`graph_nodes` & `graph_edges`**:
   - Graph topology nodes and typed edges with provenance evidence IDs.

4. **`risk_acceptances`**:
   - `acceptance_id` TEXT PRIMARY KEY, `finding_id` TEXT, `resource_arn` TEXT, `justification` TEXT, `approver` TEXT, `accepted_at` TEXT, `expires_at` TEXT, `status` TEXT.

5. **`proof_chains`**:
   - Tracks the full 20-step investigation record from finding to independent post-action verification.

6. **`proposals` (State Machine Extension)**:
   - Add columns: `lifecycle_state` TEXT, `remediation_plan_json` TEXT, `rollback_plan_json` TEXT, `post_action_verification_status` TEXT, `verified_at` TEXT.

---

## 4. Execution Plan by Priority

| Stage | Focus Area | Deliverables |
| :---: | :--- | :--- |
| **Stage 1** | Baseline Audit & Git Checkpoint | `docs/MASTER_AUDIT_REPORT.md`, branch `feature/top-tier-platform-evolution` |
| **Stage 2** | Architecture & Multi-Source Intelligence | `backend/intelligence/` (Adapters: S3, EC2, IAM, SecurityHub, Config, Prowler, Normalization, Inventory, Lifecycle) |
| **Stage 3** | Cloud Asset Graph & Attack-Path Engine | `backend/graph/` (ResourceGraph, IAM Analyzer, Attack Paths, Blast Radius, Choke Points) |
| **Stage 4** | Contextual Risk Engine & Risk Acceptance | `backend/risk/` (Deterministic Multi-Factor Engine, Versioned Policies, Risk Acceptance) |
| **Stage 5** | Proof Chain, State Machine & Verification | `backend/governance/` (14-State Machine, 20-Step Proof Chain, Rollback, Post-Action Verifier, Dossier) |
| **Stage 6** | RBAC, Observability & Compliance | `backend/rbac/`, `backend/observability/`, `backend/compliance/` (CIS, NIST, MITRE, OWASP, Metrics) |
| **Stage 7** | REST API Endpoints & Server Integration | Update `backend/server.py` with all new intelligence, graph, risk, proof-chain, compliance endpoints |
| **Stage 8** | Adversarial Assurance & Scenario Tests | Tests for Scenarios 1 to 6, fuzzing, property tests, security regression (aiming 180+ tests) |
| **Stage 9** | Dashboard Evolution | Update `dashboard/` with 5 new integrated investigation views (Intelligence, Graph, Risk, Proof Chain, Compliance) |
| **Stage 10**| DevSecOps, Supply-Chain & Final Docs | `.github/workflows/security-ci.yml`, pinned dependencies, update all documentation deliverables |
