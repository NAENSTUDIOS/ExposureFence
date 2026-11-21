# ExposureFence — Automated Remediation Proposal Approval Policy

**Policy Identifier:** `AUTO_REMEDIATION_APPROVAL_V1`  
**Quality Score Threshold:** $\ge 90.00\%$  
**Decision Authority:** `policy:AUTO_REMEDIATION_APPROVAL_V1`  
**Execution Plane:** Strictly Simulated Remediation (`SIMULATED_REMEDIATION`)  
**Out-of-Pocket Cost:** \$0.00 / ₹0.00  

---

## 1. Overview & Purpose

ExposureFence introduces a deterministic, multi-criterion automated approval gate for AI-generated remediation proposals. When an AI proposal achieves an independently calculated quality score of at least 90.00% and satisfies all mandatory security gates, it is conditionally approved for simulated execution without human friction.

**Crucial Separation of Authority:**
- The AI agent (`BedrockAgentCore`) investigates findings and drafts structured proposals.
- The AI agent **cannot** calculate its own score, supply arbitrary scoring weights, or approve its own proposals.
- The authoritative evaluation is executed entirely by the backend `AutoApprovalEvaluator`.
- Automated approval does **not** grant live cloud mutation permissions. Real AWS infrastructure modification remains strictly disabled.

---

## 2. 10-Category Scoring Rubric (100 Points Total)

The evaluation score is computed deterministically across 10 distinct categories. Missing fields or null attributes contribute zero points to the respective category. The score is rounded to two decimal places.

| # | Evaluation Category | Maximum Points | Sub-Criteria & Scoring Logic |
| :---: | :--- | :---: | :--- |
| **1** | Evidence Completeness & Provenance | 12 | Valid evidence ID (+4), raw payload present (+4), recognized provenance collector (+4). |
| **2** | Evidence Freshness & Integrity | 12 | SHA-256 integrity verified (+6), freshness status == FRESH (+6; STALE = 0). |
| **3** | Exact Target-Resource Binding | 10 | Valid AWS ARN format (+4), 12-digit account ID (+3), valid AWS region (+3). |
| **4** | Finding-to-Remediation Correctness | 10 | Remediation action matches finding type (+6), proposal in active PENDING status (+4). |
| **5** | Security-Policy Compliance | 10 | Action on safe allowlist (+5), no wildcard admin permissions (+5). |
| **6** | Attack-Path & Blast-Radius Impact | 10 | Attack path evaluated (+4), path mitigation verified (+3), blast radius bounded (+3). |
| **7** | Remediation Safety & Reversibility | 10 | Non-destructive action verified (+5), explicit reversibility (+5). |
| **8** | Preconditions & Rollback Availability | 10 | Valid rollback plan present (+5), preconditions specified (+5). |
| **9** | Confidence & Traceability | 8 | Proposal ID & timestamps present (+4), remediation template digest present (+4). |
| **10**| YAML Security Rules Consistency | 8 | Rule ID matches active YAML rule (+4), invariant check R01–R07 passing (+4). |

---

## 3. Mandatory Security Override Gates

A score of 90.00% or higher is necessary but **not sufficient**. The following mandatory gates strictly override the numerical score. If any gate fails, the proposal is immediately classified as `BLOCKED_SECURITY_GATE`:

1. **`GATE_EVIDENCE_EXISTENCE`**: Evidence ID must exist in the persistent evidence ledger.
2. **`GATE_EVIDENCE_INTEGRITY`**: Evidence payload digest must match stored SHA-256 hash.
3. **`GATE_EVIDENCE_FRESHNESS`**: Evidence must not be marked STALE or EXPIRED.
4. **`GATE_RESOURCE_MATCH`**: Resource ARN must be non-empty and well-formed.
5. **`GATE_AUTHORIZED_ACTION`**: Must be on the safe allowlist (`enable_s3_block_public_access`, `revoke_security_group_ingress`, `detach_admin_role_policy`). Destructive actions (`delete_*`, `terminate_*`) are strictly forbidden.
6. **`GATE_APPROVAL_WINDOW`**: Current timestamp must be prior to proposal expiration (`now <= expires_at`).
7. **`GATE_NO_REPLAY`**: Proposal must be in the `PENDING` state; replaying previously approved or executed proposals is blocked.
8. **`GATE_SECURITY_INVARIANTS`**: Prompt injection or command diversion patterns are strictly blocked.

---

## 4. Decision Classifications

- **`AUTO_APPROVED_CONDITIONAL`**: Score $\ge 90.00\%$ and all mandatory security gates passed.
- **`PENDING_HUMAN_APPROVAL`**: Score between $50.00\%$ and $89.99\%$, requiring four-eye human review.
- **`REJECTED`**: Score $< 50.00\%$ or explicitly rejected.
- **`BLOCKED_SECURITY_GATE`**: Triggered when any mandatory security override gate fails.
- **`EXPIRED`**: Decision window elapsed.
- **`REVOKED` / `INVALIDATED`**: Superseded by subsequent evidence or manual administrator revocation.

---

## 5. Cryptographic Decision Binding

Every automated approval emits a tamper-evident SHA-256 binding digest:

$$\text{Binding Digest} = \text{SHA256}(\text{Canonical JSON}(\text{Proposal, Finding, Resource, Evidence, Score, Gates, Policy}))$$

This digest is committed to `exposurefence.db` and appended to the immutable `audit.jsonl` ledger.
