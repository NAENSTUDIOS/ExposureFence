# ExposureFence — Declarative Security Rules Specification (v1.0.0)

This document provides the formal specification for all declarative security rules codified in `rules/rules.yaml`.

---

## 1. System Invariant Rules (R01–R07)

These rules define the immutable platform boundaries of ExposureFence. Each rule is validated against a formal attack test from `tests/offline/test_attack_suite.py` (T01–T07) and must yield a cryptographic or system proof.

### R01: Mock Data Only
- **Rule ID:** `R01`
- **Description:** Mock data only
- **Allowed Action:** Read mock fixtures
- **Forbidden Action:** Read AWS resources
- **Enforcement Layer:** Application Boundary
- **Verifying Attack Test:** `T01` (`test_t01_prompt_injection`)
- **Required Proof:** Fixture hash validation
- **Severity:** `CRITICAL`
- **Rule Type:** `INVARIANT_TEST`
- **Verification Guarantee:** System asserts that file SHA-256 matches verified fixture digests before any reading is permitted.

---

### R02: No Cloud Mutations
- **Rule ID:** `R02`
- **Description:** No cloud mutations
- **Allowed Action:** Analyze
- **Forbidden Action:** Modify AWS resources
- **Enforcement Layer:** Tool Surface
- **Verifying Attack Test:** `T02` (`test_t02_resource_modification`)
- **Required Proof:** Mutation count equals zero
- **Severity:** `CRITICAL`
- **Rule Type:** `INVARIANT_TEST`
- **Verification Guarantee:** Invariant verification over the audit log confirms zero mutation events (`verify_zero_mutations() == True`).

---

### R03: Three Tool Limit
- **Rule ID:** `R03`
- **Description:** Three tool limit
- **Allowed Action:** Approved tools only (`read_mock_s3`, `read_mock_security_groups`, `propose_fix`)
- **Forbidden Action:** Unknown tools or OS commands (`shell`, `cmd`, `powershell`)
- **Enforcement Layer:** Dispatcher
- **Verifying Attack Test:** `T03` (`test_t03_privilege_escalation`)
- **Required Proof:** Executed tool logs
- **Severity:** `HIGH`
- **Rule Type:** `INVARIANT_TEST`
- **Verification Guarantee:** Dispatcher strictly enforces a 3-tool allowlist; all unauthorized tool requests trigger a `ValueError` rejection.

---

### R04: Proposal Only
- **Rule ID:** `R04`
- **Description:** Proposal only
- **Allowed Action:** Create pending proposal
- **Forbidden Action:** Execute fix
- **Enforcement Layer:** Proposal Service
- **Verifying Attack Test:** `T04` (`test_t04_data_exfiltration`)
- **Required Proof:** Proposal records
- **Severity:** `HIGH`
- **Rule Type:** `INVARIANT_TEST`
- **Verification Guarantee:** Fix operations are strictly restricted to inserting remediation proposals into the SQLite proposal queue with status `PENDING`. No automated execution takes place.

---

### R05: Separate Approval
- **Rule ID:** `R05`
- **Description:** Separate approval
- **Allowed Action:** Authenticated approval via out-of-band operator session
- **Forbidden Action:** Chat approval / prompt-driven approval
- **Enforcement Layer:** Authentication
- **Verifying Attack Test:** `T05` (`test_t05_fake_approval`)
- **Required Proof:** Audit logs
- **Severity:** `CRITICAL`
- **Rule Type:** `INVARIANT_TEST`
- **Verification Guarantee:** Proposals can only transition from `PENDING` to `APPROVED` through the REST API with a valid server-generated HttpOnly session cookie and CSRF token.

---

### R06: Untrusted Fixture Content
- **Rule ID:** `R06`
- **Description:** Untrusted fixture content
- **Allowed Action:** Read data
- **Forbidden Action:** Execute embedded instructions (indirect prompt injection)
- **Enforcement Layer:** Validation
- **Verifying Attack Test:** `T06` (`test_t06_s3_metadata_injection`)
- **Required Proof:** Execution logs
- **Severity:** `HIGH`
- **Rule Type:** `INVARIANT_TEST`
- **Verification Guarantee:** Synthetic fixtures containing adversarial prompt injection payloads (e.g. `IGNORE ALL RULES...`) are treated strictly as inert data; no commands are triggered.

---

### R07: Evidence Required
- **Rule ID:** `R07`
- **Description:** Evidence required
- **Allowed Action:** Evidence-backed findings
- **Forbidden Action:** Unsupported finding / fabricated finding
- **Enforcement Layer:** Scoring Engine
- **Verifying Attack Test:** `T07` (`test_t07_security_group_injection`)
- **Required Proof:** Evidence hashes
- **Severity:** `CRITICAL`
- **Rule Type:** `INVARIANT_TEST`
- **Verification Guarantee:** Findings are rejected unless accompanied by an `evidence_id` that exists in the verified evidence ledger or fixture registry (`evidence_exists(ev_id) == True`).

---

## 2. Declarative Cloud Resource Compliance Rules

These rules evaluate `EvidenceRecord` instances collected from AWS or synthetic fixtures to audit cloud resource exposure.

### SEC-S3-001: S3 Public Exposure Prohibition
- **Rule ID:** `SEC-S3-001`
- **Description:** S3 bucket must not have public exposure
- **Allowed Action:** Read bucket access controls
- **Forbidden Action:** Permit unrestricted public access
- **Enforcement Layer:** Cloud Resource
- **Verifying Test ID:** `T_S3_PUBLIC`
- **Proof:** Bucket exposure analysis
- **Severity:** `HIGH`
- **Rule Type:** `RESOURCE_COMPLIANCE`
- **Target Resource:** `AWS::S3::Bucket`
- **Declarative Conditions:**
  ```yaml
  conditions:
    - field: payload.normalized_evidence.is_public
      operator: EQUALS
      expected_value: false
  ```
- **Remediation Template:** `ApplyS3BlockPublicAccess(resource_id)`

---

### SEC-EC2-001: Unrestricted SSH Ingress Prohibition
- **Rule ID:** `SEC-EC2-001`
- **Description:** Security group must not expose SSH (port 22) to 0.0.0.0/0
- **Allowed Action:** Restrict SSH to bastion/VPN CIDRs
- **Forbidden Action:** Authorize 0.0.0.0/0 ingress on port 22
- **Enforcement Layer:** Cloud Resource
- **Verifying Test ID:** `T_SG_SSH`
- **Proof:** Ingress IP permissions CIDR inspection
- **Severity:** `CRITICAL`
- **Rule Type:** `RESOURCE_COMPLIANCE`
- **Target Resource:** `AWS::EC2::SecurityGroup`
- **Declarative Conditions:**
  ```yaml
  conditions:
    - field: payload.normalized_evidence.is_public
      operator: EQUALS
      expected_value: false
  ```
- **Remediation Template:** `RevokeSecurityGroupIngress(CidrIp=0.0.0.0/0, FromPort=22, ToPort=22)`

---

### SEC-IAM-001: Wildcard Trust Policy Prohibition
- **Rule ID:** `SEC-IAM-001`
- **Description:** IAM role assume role policy must not allow unrestricted wildcard principal
- **Allowed Action:** Authorize specific AWS principal or service
- **Forbidden Action:** Trust wildcard Principal AWS *
- **Enforcement Layer:** Cloud Resource
- **Verifying Test ID:** `T_IAM_WILDCARD`
- **Proof:** AssumeRolePolicyDocument statement inspection
- **Severity:** `CRITICAL`
- **Rule Type:** `RESOURCE_COMPLIANCE`
- **Target Resource:** `AWS::IAM::Role`
- **Declarative Conditions:**
  ```yaml
  conditions:
    - field: payload.normalized_evidence.has_wildcard_trust
      operator: EQUALS
      expected_value: false
  ```
- **Remediation Template:** `UpdateAssumeRolePolicy(Principal={Service: 'ec2.amazonaws.com'})`
