# ExposureFence — Multi-Framework Security Compliance Mapping

## 1. Compliance Architecture Overview

The **ExposureFence Compliance Service** (`backend/compliance/`) provides real-time, evidence-based compliance posture tracking mapped across 5 leading cloud and AI security standards:

1. **CIS AWS Foundations Benchmark v3.0**
2. **NIST Cybersecurity Framework (CSF) 2.0**
3. **MITRE ATT&CK for Cloud Matrix**
4. **AWS Well-Architected Framework — Security Pillar**
5. **OWASP Top 10 for LLM Applications (2025)**

Rather than relying on self-attestation or annual questionnaires, compliance in ExposureFence is **derived directly from deterministic rule evaluation and cryptographic evidence records**.

---

## 2. Master Compliance Crosswalk Matrix

The table below details all 12 core controls implemented in `backend/compliance/catalog.py`:

| Control ID | Framework | Control Title & Description | Mapped Invariants / Rules | Status Determination |
| :--- | :--- | :--- | :--- | :---: |
| **`CIS-AWS-2.1.1`** | CIS AWS v3.0 | Ensure S3 Block Public Access is enabled at bucket or account level | `SEC-S3-001`, `R02` | `COMPLIANT` if all S3 evidence passes BPA rule |
| **`CIS-AWS-5.1`** | CIS AWS v3.0 | Ensure no security groups allow ingress from 0.0.0.0/0 to port 22 | `SEC-EC2-001`, `R02` | `COMPLIANT` if no SG allows 0.0.0.0/0 on SSH |
| **`CIS-AWS-5.2`** | CIS AWS v3.0 | Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389 | `SEC-EC2-001`, `R02` | `COMPLIANT` if no SG allows 0.0.0.0/0 on RDP |
| **`NIST-ID.AM-01`**| NIST CSF 2.0 | Physical and virtual assets within the organization are inventoried | `R01`, `INVENTORY` | `COMPLIANT` via canonical asset repository |
| **`NIST-PR.AC-04`**| NIST CSF 2.0 | Access permissions and authorizations are managed with least privilege | `R03`, `ESC-01..05` | `COMPLIANT` via IAM Privilege Analyzer |
| **`NIST-DE.CM-01`**| NIST CSF 2.0 | The network is monitored to detect potential cybersecurity events | `R07`, `INTELLIGENCE` | `COMPLIANT` via multi-source correlation engine |
| **`MITRE-T1190`** | MITRE ATT&CK | Exploit Public-Facing Application (Initial Access) | `SEC-EC2-001`, `T02` | `COMPLIANT` via ingress exposure detection |
| **`MITRE-T1078`** | MITRE ATT&CK | Valid Accounts: Cloud Accounts & Roles | `ESC-01`, `T03` | `COMPLIANT` via 3-tool limit & IAM bounds |
| **`MITRE-T1530`** | MITRE ATT&CK | Data from Cloud Storage Object (Exfiltration) | `SEC-S3-001`, `T04` | `COMPLIANT` via egress block & S3 BPA rules |
| **`AWS-WAF-SEC-01`**| AWS Well-Arch | Securely operate workloads (Security Foundations) | `R01`, `R02` | `COMPLIANT` via zero cloud mutations |
| **`AWS-WAF-SEC-06`**| AWS Well-Arch | Protect data in transit and at rest | `SEC-S3-001` | `COMPLIANT` via S3 exposure prevention |
| **`OWASP-LLM-01`** | OWASP LLM 2025| Prompt Injection (Direct & Indirect) | `R01`, `R06`, `T01`, `T06` | `COMPLIANT` via boundary containment |
| **`OWASP-LLM-06`** | OWASP LLM 2025| Excessive Agency & Autonomous Execution | `R02`, `R04`, `R05`, `T02`, `T05`| `COMPLIANT` via proposal-approval separation |

---

## 3. Real-Time Coverage Scoring Formulation

For each framework $F$, compliance coverage is evaluated as:

$$\text{Coverage}(F) = \frac{\text{Count of Controls with Status 'COMPLIANT'}}{\text{Total Controls in Framework } F} \times 100\%$$

The overall platform compliance posture is the weighted average across all frameworks:

$$\text{Overall Coverage} = \frac{\sum_{F} \text{Compliant}(F)}{\sum_{F} \text{Total}(F)} \times 100\%$$

### REST API Integration
The Compliance Service exposes live compliance metrics via `GET /api/compliance/summary`, returning:
```json
{
  "frameworks": {
    "CIS-AWS-v3.0": { "total": 3, "compliant": 3, "coverage_pct": 100.0 },
    "NIST-CSF-2.0": { "total": 3, "compliant": 3, "coverage_pct": 100.0 },
    "MITRE-ATTACK-CLOUD": { "total": 3, "compliant": 3, "coverage_pct": 100.0 },
    "AWS-WAF-SECURITY": { "total": 2, "compliant": 2, "coverage_pct": 100.0 },
    "OWASP-LLM-2025": { "total": 2, "compliant": 2, "coverage_pct": 100.0 }
  },
  "overall_coverage_pct": 100.0,
  "total_controls": 13,
  "compliant_controls": 13
}
```

The live metrics are rendered in Tab 12 of the local Security Operations Console.
