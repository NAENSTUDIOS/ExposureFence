# ExposureFence — Open-Source Governance, Multi-Cloud Extensibility & Architecture

**Classification:** Open-Source Software Architecture  
**Primary Maintainer:** NAENSTUDIOS  
**License:** MIT License  
**Financial Policy:** Permanent \$0.00 / ₹0.00 Out-of-Pocket Spend  

---

## 1. Multi-Cloud Extensibility Architecture

ExposureFence is designed with **provider-neutral core abstractions**, allowing the governance engine, evidence ledger, rules compiler, and state machine to remain cloud-agnostic:

```
                      [ CORE GOVERNANCE KERNEL ]
             Evidence Ledger | Proof Chain | State Machine
                                   │
             ┌─────────────────────┼─────────────────────┐
             ▼                     ▼                     ▼
     [ AWS ADAPTER ]       [ AZURE ADAPTER ]     [ GCP ADAPTER ]
     S3, EC2, IAM, SH      Blob, VM, Entra ID    GCS, GCE, Cloud IAM
```

### Provider-Neutral Interfaces (`backend/adaptive/models.py`)
- `CloudProvider`: Enum supporting `AWS`, `AZURE`, `GCP`, `KUBERNETES`, and `MULTI_CLOUD`.
- `CanonicalFinding`: Normalizes multi-cloud security findings into standard severity, resource ARN, and compliance tags.
- `EvidenceRecord`: Ingests RFC 8785 canonical JSON fixtures from any cloud provider API without altering cryptographic hashing logic.

---

## 2. Contributor Guidelines & Architecture Decision Records (ADRs)

1. **Deterministic Testing Requirement:**
   - Every contribution must include deterministic offline unit and integration tests.
   - Tests must execute in $<15$ seconds without invoking live paid cloud APIs or paid LLM inference.
2. **Four-Eye Role-Based Access Control:**
   - AI models and autonomous agents are architecturally categorized as `ai_agent` and strictly barred from approving proposals or adaptations.
   - Changes to governance policies or security rules require authenticated `ADMINISTRATOR` or `APPROVER` authorization.
3. **Zero-Mutation Safety:**
   - All external connector operations default to read-only mode (`Get*`, `Describe*`, `List*`).
   - Remediation proposals are executed in offline simulation (`SIMULATED_REMEDIATION`) unless explicit operator-controlled live execution flags are passed.

---

## 3. Vulnerability Disclosure & Security Policy

Security issues should be reported directly to the maintainers via private channels:
- **Email:** `security@naenstudios.com`
- **Scope:** Invariant bypasses, privilege escalation vulnerabilities, authentication/session hijacking, or prompt injection boundary escapes.
- **Timeline:** Initial acknowledgement within 48 hours; public release after patch verification in `tests/offline`.
