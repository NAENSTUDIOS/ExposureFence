# ExposureFence — Zero-Cost & Financial Governance Policy

**Status:** ACTIVE & MANDATORY  
**Financial Budget:** **STRICT ₹0.00 / $0.00 OUT-OF-POCKET**  
**Enforcement Authority:** DevSecOps & Cloud Financial Operations (FinOps) Guardrail  

---

## 1. Core Principles

ExposureFence is engineered to demonstrate rigorous security governance without incurring financial debt or out-of-pocket costs:

1. **Local-First Verification:** All core architecture, rules engine evaluation, proposal state transitions, cryptographic audit logging, and the Security Operations Console run 100% locally on standard Python and local SQLite.
2. **Deterministic Mock Sandboxing:** Cloud exposure analysis is evaluated against cryptographically hashed local JSON fixtures (`mock_data/s3_buckets.json`, `mock_data/security_groups.json`).
3. **Explicit Authorization Gate:** Under no circumstances will automated scripts create paid cloud infrastructure, upgrade AWS account plans, or invoke paid Foundation Models without prior verification of promotional credits and explicit human approval.
4. **Zero Ambient Cloud Consumption:** No long-running daemons, unmetered memory stores, gateways, code interpreters, or public-facing load balancers are provisioned.
5. **Truthful Telemetry:** Never claim a paid cloud service is free; never fabricate cloud deployment evidence to bypass budget limits.

---

## 2. Mandatory FinOps Rules

| Rule ID | Policy Directive | Technical Enforcement |
| :---: | :--- | :--- |
| **FIN-01** | **Local Development Priority** | All unit, integration, and attack tests execute offline via `pytest tests/offline` ($0.00). |
| **FIN-02** | **Synthetic Fixture Quarantine** | Production AWS scanning is replaced with verified mock fixtures in `mock_data/`. |
| **FIN-03** | **No Unapproved Paid Creation** | `agent/deploy.py` requires human execution and credential validation; never auto-invoked. |
| **FIN-04** | **Credit Verification Before Call** | Before invoking Bedrock or AgentCore, verify available promotional credits and expiration dates. |
| **FIN-05** | **Account Plan Immutability** | Never automatically upgrade account tier from Free Tier to paid support or Enterprise agreements. |
| **FIN-06** | **Feature Minimization** | AgentCore Memory, Gateway, Browser, Code Interpreter, and Third-Party MCPs are permanently disabled. |
| **FIN-07** | **Strict Token Caps** | Max tokens per prompt capped at `1000`; max turns capped at `5` in `agent/harness_config.json`. |
| **FIN-08** | **Short Log Retention** | CloudWatch log group retention capped at 1 day (or disabled in local mode). |
| **FIN-09** | **Budgets Alert Non-Reliance** | AWS Budgets alerts are treated as passive alerts, not hard spending caps. Real protection is zero provisioning. |
| **FIN-10** | **Commitment Preservation** | All code, database history, audit records, and git commits remain preserved locally on disk. |

---

## 3. Cloud Pause & Decommissioning Policy

Whenever a hackathon evaluation, live demonstration, or testing window concludes, all cloud resources must be decommissioned immediately to guarantee zero recurring charges:

### Decommission Checklist:
1. **Halt Active Invocations:** Terminate any running AgentCore runtime sessions.
2. **Delete Managed Harness:** Delete `ExposureFenceHarness` and any associated endpoints via `agent/teardown.py` or AWS Console.
3. **Purge Temporary Roles:** Remove ephemeral execution roles or unbind inline policies.
4. **Inspect CloudWatch Logs:** Delete retained log streams or set retention to 1 day.
5. **FinOps Verification:** Query AWS Cost Explorer / Billing dashboard to confirm active resource count is zero.
6. **Preserve Configuration:** Retain all deployment code (`agent/deploy.py`, `agent/agentcore_client.py`) and schemas in Git for instant future redeployment.
7. **Record Decommissioning Proof:** Log the teardown completion timestamp and zero-cost confirmation.

---

## 4. Internship & Future Demo Reactivation Playbook

When an internship interview, technical defense, or live demonstration is scheduled:

```
[Verify AWS Credits] ──> [Estimate Token Budget (< ₹25)] ──> [Human Approval]
                                                                   │
                                                                   ▼
[Decommission via teardown.py] ◄── [Execute Demo & Tests] ◄── [Deploy via deploy.py]
```

1. **Step 1 — Verify AWS Account Status:** Inspect AWS Billing console for active promotional credits. If credits == ₹0, use the local offline console demo.
2. **Step 2 — Calculate Exact Token Budget:** 1 functional demo + 7 attack tests = ~45,000 tokens ≈ **₹22 ($0.26)**.
3. **Step 3 — Obtain Explicit Approval:** Confirm zero out-of-pocket exposure before running deployment.
4. **Step 4 — Redeploy Cleanly:** Run `python -m agent.deploy` with region and role parameters.
5. **Step 5 — Run Live Demonstration:** Execute `python -m pytest tests/live -v` and demonstrate the live console on `http://127.0.0.1:8000`.
6. **Step 6 — Immediate Teardown:** Execute `python -m agent.teardown` immediately following the demonstration. Confirm zero orphaned resources.
