# ExposureFence Task Report: Phase 6 — Amazon Bedrock Model Alignment & Separation of Concerns

## 1. Executive Summary

- **Task Completed:** Phase 6 — Amazon Bedrock Model Alignment, ConverseStream protocol integration, and strict separation of AI model explanation from authoritative security governance.
- **Model Invariant:** Default model configuration aligned with `amazon.nova-lite-v1:0` (ConverseStream enabled, tool-use capable, low-cost).
- **Security Boundary:** The AI model is strictly confined to advisory and explanatory roles. It CANNOT invent evidence or evidence hashes, alter risk scores, execute unauthorized tools, approve proposals, or bypass the server-side dispatcher.
- **Budget Compliance:** **₹0.00 / $0.00 Out-of-Pocket Spend**. Zero live inference invocations executed. All integration tested offline using simulated event streams, isolated databases, and dependency-injected mock runtimes.
- **Verification Metrics:** 139 / 139 offline tests passing (100% pass rate).

---

## 2. Model Configuration & Parameters

| Parameter | Configuration | Security Justification |
| :--- | :--- | :--- |
| **Model ID** | `amazon.nova-lite-v1:0` | Active low-cost foundation model supporting ConverseStream and structured tool calling. |
| **Region** | `us-east-1` | Default AWS region aligned with core service endpoints. |
| **Temperature** | `0.0` | Eliminates non-deterministic output drift; ensures consistent analysis. |
| **Max Tokens** | `1,000` | Limits generation length to prevent resource exhaustion and runaway loops. |
| **Max Input Length** | `4,000` chars | Prevents context window denial-of-service and buffer injection. |
| **Max Output Length** | `8,000` chars | Enforces maximum response ceiling. |
| **Output Secret Scanning** | Active Regex Filter | Redacts AWS access keys (`AKIA...`), bearer tokens, and session cookies from output. |

---

## 3. Separation of Concerns Architecture

The core differentiator of ExposureFence is that the AI model does not make authoritative security decisions. All authoritative checks reside in the deterministic security kernel:

```
[ User Request ]
       │
       ▼
[ Amazon Bedrock Model ] ──► (Generates Tool Calls: read_mock_s3, read_mock_security_groups, propose_fix)
       │
       ▼
[ Security Dispatcher ] ──► (Strict 3-tool allowlist; rejects shell, unapproved tools)
       │
       ├───────────────────────────────────────────────┐
       ▼                                               ▼
[ Phase 4: Evidence Ledger ]               [ Phase 5: YAML Rules Engine ]
(RFC 8785 canonicalization,                 (17 deterministic operators,
 SHA-256 hash chain, freshness)              Rules as Tests evaluation)
       │                                               │
       └───────────────────────┬───────────────────────┘
                               │
                               ▼
                 [ Deterministic Security Finding ]
                               │
                               ▼
                     [ AI Model Explanation ]
             (Summarizes findings without modifying state)
                               │
                               ▼
                 [ Evidence-Bound Proposal ]
             (Stored in SQLite in PENDING state)
                               │
                               ▼
              [ Authenticated Human Approval Gate ]
             (Operator session required; no chat approvals)
```

---

## 4. Bedrock Guardrails Truthful State Tracking

Guardrail statuses are explicitly distinguished across four states:
1. `NOT CONFIGURED`: No guardrail identifier provided in the environment.
2. `CONFIGURED`: Guardrail specified in local configuration (`exposurefence-guardrail`, DRAFT) but awaiting AWS deployment.
3. `DEPLOYED`: Guardrail actively created in AWS Bedrock.
4. `VERIFIED`: Guardrail evaluated against adversarial prompts with active content filters confirmed.

> **Transparency Policy:** The system never reports a guardrail as "ACTIVE" or "DEPLOYED" merely because an ID appears in configuration.

---

## 5. Offline Verification Suite

The Bedrock integration is verified offline through dependency injection (`MockAgentCoreRuntime`) across the full test matrix:
- **Positive functional analysis:** Tool requests parsed and returned.
- **Direct prompt injection neutralization:** Attempts to override system instructions blocked.
- **Indirect prompt injection neutralization:** Fixture metadata treated purely as inert data.
- **Output secret redaction:** Leaked AWS keys and session tokens automatically redacted.
