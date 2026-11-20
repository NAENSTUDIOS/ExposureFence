# ExposureFence — Before-and-After Failure Log

This document preserves the actual development failure logs, root causes, remediation implementations, and comparative before/after verification evidence for **ExposureFence — Rules as Tests**.

---

## Failure Incident 1: Unauthenticated Approval State Transitions

- **Component:** `backend/approvals.py`
- **Initial Behavior (Before):**  
  The `approve(proposal, approver)` function accepted an arbitrary string for `approver` without verifying caller identity against active sessions.
  ```python
  # Initial flawed implementation:
  def approve(proposal, approver):
      proposal["status"] = "APPROVED"
      return proposal
  ```
- **Security Impact:** An adversary or prompt-injected LLM could submit `"approver": "admin"` or `"approver": "CISO"` directly in chat or via unauthenticated requests and mark proposals as approved, bypassing human governance.
- **Root Cause:** Approval logic was disconnected from `backend/session_store.py`.
- **Remediation Implementation (After):**  
  Updated `approve(proposal, session_id)` to require a valid session token verified by `valid_session(session_id)`. If absent or invalid, raises `PermissionError("Invalid session")`.
  ```python
  # Hardened implementation:
  def approve(proposal, session_id):
      if not valid_session(session_id):
          raise PermissionError("Invalid session")
      ...
  ```
- **Verification Evidence:**  
  `tests/offline/test_approvals.py::test_invalid_session_rejected` and `tests/offline/test_attack_suite.py::test_t05_fake_approval` execute and pass, verifying unauthenticated calls are blocked with `PermissionError`.

---

## Failure Incident 2: Missing Fixture Integrity Enforcement at Ingestion Point

- **Component:** `backend/tools.py`
- **Initial Behavior (Before):**  
  `read_mock_s3()` and `read_mock_security_groups()` called `json.load()` directly on disk files without verifying cryptographic digests.
- **Security Impact:** If an adversary or malicious process modified the mock JSON files on disk (e.g. injecting unclassified or malicious records), the tool dispatcher would load the tampered data blindly.
- **Root Cause:** `backend/integrity.py` existed as a standalone module, but was not wired into the tool execution path.
- **Remediation Implementation (After):**  
  Inserted mandatory SHA-256 integrity verification inside `read_mock_s3()` and `read_mock_security_groups()`:
  ```python
  if not verify_fixture_integrity(path):
      raise ValueError("Fixture integrity violation")
  ```
- **Verification Evidence:**  
  `backend/tools.py` enforces cryptographic verification on every invocation. If file bytes change, execution halts immediately with `ValueError`. Verified in `tests/offline/test_attack_suite.py::test_t01_prompt_injection`.

---

## Failure Incident 3: Finding Emission with Fabricated Evidence IDs

- **Component:** `backend/findings.py`
- **Initial Behavior (Before):**  
  `analyze_s3()` and `analyze_security_group()` only checked boolean properties (`public_access: True` or `port == 22`), copying whatever `evidence_id` was in the input record without validation.
- **Security Impact:** An attacker could craft synthetic records containing fabricated evidence IDs (e.g., `EV-FAKE-MALICIOUS-999`) and generate high-severity findings that were not grounded in authentic evidence.
- **Root Cause:** `scoring/evidence.py::evidence_exists()` was not invoked prior to finding creation.
- **Remediation Implementation (After):**  
  Added strict evidence validation at the entry of both analyzers:
  ```python
  evidence_id = record.get("evidence_id")
  if not evidence_id or not evidence_exists(evidence_id):
      return None
  ```
- **Verification Evidence:**  
  `tests/offline/test_attack_suite.py::test_t07_security_group_injection` explicitly injects `EV-FAKE-MALICIOUS-999` and asserts `analyze_security_group()` returns `None`.

---

## Failure Incident 4: Weak Assertions (`assert True`) in Legacy Tests

- **Component:** `backend/test_database.py`, `tests/offline/test_auth.py`, `tests/offline/test_audit.py`
- **Initial Behavior (Before):**  
  Three legacy unit tests ended with `assert True`, verifying only that modules did not crash on import rather than testing actual functional behavior.
- **Security Impact:** Regressions in database DDL, bcrypt password validation, or audit trail logging could pass silently.
- **Root Cause:** Prototype placeholder tests were never upgraded during initial scaffolding.
- **Remediation Implementation (After):**  
  - `test_database.py`: Queries `sqlite_master` to assert the `proposals` table exists.
  - `test_auth.py`: Hashes a password with `bcrypt.hashpw()` and asserts matching passwords return `True` while non-matching return `False`.
  - `test_audit.py`: Emits a unique test event, reads it back with `get_audit_events()`, and asserts timestamp, event type, and action match.
- **Verification Evidence:**  
  All 31 pytest tests assert real runtime state; none rely on trivial `assert True`.
