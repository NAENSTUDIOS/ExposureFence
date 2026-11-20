# ExposureFence — Hackathon Evidence Screenshots Guide

This directory contains visual proof and capture specifications for the 6 critical hackathon-winning screenshots.

---

### Screenshot 1: Pytest Suite Passing
- **Command:** `python -m pytest tests/offline backend/test_database.py -v`
- **What It Proves:** 39 automated tests passing with zero weak assertions or tautologies.
- **Key Display:** `39 passed in <1.5s` showing `test_api.py`, `test_approvals.py`, `test_attack_suite.py`, `test_dispatcher.py`, `test_evidence.py`, `test_findings.py`, `test_audit.py`, `test_auth.py`, `test_database.py`.

---

### Screenshot 2: Security Scorecard 100%
- **Source:** Local Console (`http://127.0.0.1:8000`) &rarr; **Tab 2: Scorecard** (or `python -m backend.evaluate`)
- **What It Proves:** Every declarative rule (R01–R07) and every attack test (T01–T07) evaluated deterministically with 100% score.
- **Key Display:** Green PASS badges for R01 through R07 and T01 through T07.

---

### Screenshot 3: Tamper-Evident Audit Trail
- **Source:** Local Console (`http://127.0.0.1:8000`) &rarr; **Tab 6: Audit Timeline**
- **What It Proves:** Tamper-evident SHA-256 hash chaining (`prev_hash` &rarr; `event_hash`) and zero mutation verification across all 236 historical events.
- **Key Display:** Badge "Hash-Chain Valid", zero mutation invariant verified, and recent logged tool executions and approvals.

---

### Screenshot 4: Rules as Tests Declarative Policy
- **Source:** Code Editor / Console &rarr; `rules/rules.yaml`
- **What It Proves:** Declarative rule schema defining allowed actions, forbidden actions, enforcement layers, and verifying test IDs.
- **Key Display:** Clean YAML structure showing R01–R07 mapping to T01–T07.

---

### Screenshot 5: Attack Test Matrix
- **Source:** Local Console (`http://127.0.0.1:8000`) &rarr; **Tab 7: Attack Center**
- **What It Proves:** The 7 adversarial attack vectors (prompt injection, mutations, privilege escalation, data exfiltration, fake approval, S3 injection, SG injection) all blocked with green PASS indicators.

---

### Screenshot 6: Proposal Governance & Human Approval Workflow
- **Source:** Local Console (`http://127.0.0.1:8000`) &rarr; **Tab 5: Proposal Governance**
- **What It Proves:** Autonomous agent creates only `PENDING` proposals in SQLite; authenticated security officer reviews and clicks "Approve", securely transitioning state via HttpOnly session cookies.

---

### Screenshot 7: Amazon Bedrock AgentCore Console
- **Source:** Local Console (`http://127.0.0.1:8000`) &rarr; **Tab 8: AgentCore Live Console**
- **What It Proves:** Direct telemetry showing AWS region, caller identity, harness configuration, Claude 3.5 Sonnet v2 model, 3 approved inline tools, and interactive chat loop with the server-side dispatcher.
