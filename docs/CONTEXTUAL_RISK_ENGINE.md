# ExposureFence — Contextual Risk Engine & Risk Acceptance Registry

## 1. Overview & Problem Statement

Conventional cloud security tools compute risk scores based purely on static CVSS or scanner severity (e.g., all "Public S3 Buckets" are scored at 9.0). This creates alert fatigue and ignores operational context.

An S3 bucket containing public marketing assets has vastly lower true risk than an S3 bucket storing financial database backups accessible via an internet-facing EC2 instance running administrative roles.

The **ExposureFence Contextual Risk Engine** (`backend/risk/`) dynamically evaluates risk by synthesizing:
1. Finding severity and asset criticality.
2. Network exposure posture.
3. Attack-path reachability.
4. IAM privilege escalation potential.
5. Downstream blast radius.
6. Evidence integrity and temporal freshness.
7. Explicit, time-bounded risk acceptance records.

---

## 2. Versioned Risk Policies

The engine supports versioned policies to ensure auditability and backward compatibility:

### 2.1 Policy V1 (`RiskPolicyV1` — Legacy Static)
Maps finding severity directly to static numbers:
- `CRITICAL`: 90.0
- `HIGH`: 70.0
- `MEDIUM`: 50.0
- `LOW`: 30.0

### 2.2 Policy V2 (`RiskPolicyV2` — Multi-Factor Contextual)
A composite algorithm weighting five distinct operational factors:

$$\text{Base Score} = \sum_{i=1}^{5} w_i \times F_i$$

| Factor ($F_i$) | Weight ($w_i$) | Source Metric | Description |
| :--- | :---: | :--- | :--- |
| **Asset Criticality** | **0.25** | Asset metadata (`CRITICAL`, `CONFIDENTIAL`, `PUBLIC`) | Business value of target resource |
| **Network Exposure** | **0.25** | CIDR and Port configuration | Degree of exposure to untrusted public CIDRs (`0.0.0.0/0`) |
| **Reachability** | **0.20** | Graph Attack Path Engine | Presence and confidence of viable multi-hop attack paths |
| **IAM Privilege** | **0.15** | IAM Analyzer | Presence of administrative or escalation permissions |
| **Blast Radius** | **0.15** | Blast Radius Engine | Number of downstream assets and sensitive resources in scope |

$$\text{Base Score} = 0.25 F_{\text{crit}} + 0.25 F_{\text{exp}} + 0.20 F_{\text{reach}} + 0.15 F_{\text{iam}} + 0.15 F_{\text{blast}}$$

---

## 3. Dynamic Modifiers: Integrity & Freshness

The calculated base score is adjusted by evidence quality modifiers:

$$\text{Contextual Score} = \text{Base Score} \times \text{Integrity Factor} \times \text{Freshness Factor}$$

### 3.1 Evidence Integrity Factor
- `VERIFIED` / `VERIFIED_FIXTURE`: **1.00** (Full confidence)
- `TAMPERED` / `HASH_MISMATCH`: **0.00** (Score invalidated, alert raised)
- `UNVERIFIED`: **0.85** (Penalized for missing verification)

### 3.2 Evidence Freshness Factor
- `FRESH` ($\le$ 24 hours): **1.00**
- `STATIC_FIXTURE`: **1.00**
- `STALE` (> 24 hours): **0.70** (Decayed due to aging telemetry)

---

## 4. Formal Risk Acceptance Registry (`acceptance.py`)

ExposureFence provides a cryptographic, audited mechanism for security teams to accept risk with mandatory justification and time-to-live (TTL) limits.

```
[ Finding Ingested ] ──► [ Evaluate Policy V2: Score = 87.5 ]
                                    │
                                    ▼
                     [ Check Risk Acceptance Registry ]
                                    │
                      ┌─────────────┴─────────────┐
                      ▼                           ▼
            [ Active Acceptance ]       [ No Acceptance / Expired ]
                      │                           │
                      ▼                           ▼
         Effective Score: 0.0        Effective Score: 87.5
         Status: SUPPRESSED          Status: ACTIVE / PENDING
```

### 4.1 Data Model (`RiskAcceptance`)
- `acceptance_id`: Unique identifier (`ACC-<hex>`).
- `finding_id`: Bound finding ID.
- `justification`: Mandatory business justification (e.g., *"Public assets bucket for static documentation"*).
- `accepted_by`: Authenticated security officer username.
- `created_at`: UTC ISO timestamp.
- `expires_at`: UTC ISO timestamp (mandatory expiration).
- `revoked`: Boolean flag for early revocation.

### 4.2 Lifecycle & Automatic Expiration
- When active, the finding's effective risk score is reduced to `0.0` and its lifecycle state shifts to `SUPPRESSED`.
- When `expires_at` is reached, `is_active()` evaluates to `False`, the acceptance becomes inactive, and the finding automatically reverts to its full unmitigated risk score and `ACTIVE` state.
- Security officers can manually revoke an acceptance at any time via `revoke_acceptance(acceptance_id)`.

---

## 5. Verification & Testing

The Contextual Risk Engine is verified by 6 dedicated offline tests in `tests/offline/test_risk.py`:
- `test_risk_policy_v1_legacy_scoring`: Validates legacy mapping.
- `test_risk_policy_v2_multifactor_calculation`: Validates weighted composite calculation.
- `test_risk_modifiers_integrity_and_freshness`: Validates integrity and freshness multiplier behavior.
- `test_risk_acceptance_lifecycle`: Validates creation, active status, and effective score zeroing.
- `test_risk_acceptance_expiration_and_revocation`: Validates automatic score reversion upon TTL expiration or revocation.
- `test_risk_engine_integration`: Validates end-to-end integration with multi-source findings and graph attack paths.
