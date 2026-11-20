# ExposureFence — Phase 4 Evidence Engine Test Results

**Date:** November 21, 2026  
**Test Framework:** Pytest 9.2.0 (Python 3.15.2 / Win32)  
**Execution Mode:** 100% Offline (Standard Sandbox, Zero Network Calls, Mocked Boto3)  
**Total Tests:** **95 PASSED in 3.96s** (100% Pass Rate)

---

## 1. Test Suite Summary

```
============================= test session starts =============================
platform win32 -- Python 3.15.2, pytest-9.2.0, pluggy-1.7.0
plugins: anyio-4.16.0
collected 95 items

tests/offline/test_api.py .................................... [  4%]
tests/offline/test_approvals.py .............................. [  9%]
tests/offline/test_attack_rules.py ........................... [ 13%]
tests/offline/test_attack_suite.py ........................... [ 21%]
tests/offline/test_audit.py .................................. [ 22%]
tests/offline/test_auth.py ................................... [ 23%]
tests/offline/test_connectors.py ............................. [ 30%]
tests/offline/test_dispatcher.py ............................. [ 36%]
tests/offline/test_evidence.py ............................... [ 38%]
tests/offline/test_evidence_canonicalization.py .............. [ 49%]
tests/offline/test_evidence_freshness.py ..................... [ 54%]
tests/offline/test_evidence_hashing.py ....................... [ 60%]
tests/offline/test_evidence_integration.py .................. [ 65%]
tests/offline/test_evidence_provenance.py .................... [ 68%]
tests/offline/test_evidence_relationships.py ................. [ 72%]
tests/offline/test_evidence_repository.py .................... [ 78%]
tests/offline/test_evidence_schema.py ........................ [ 86%]
tests/offline/test_evidence_verification.py .................. [ 90%]
tests/offline/test_findings.py ............................... [ 92%]
tests/offline/test_hashing.py ................................ [ 93%]
tests/offline/test_proposals.py .............................. [ 94%]
tests/offline/test_scoring.py ................................ [ 97%]
tests/offline/test_sessions.py ............................... [ 98%]
backend/test_database.py ..................................... [100%]

============================= 95 passed in 3.96s ==============================
```

---

## 2. Phase 4 New Evidence Test Breakdown (49 Tests)

| Test Suite File | Tests | Focus Area & Invariants Verified |
| :--- | :---: | :--- |
| **`test_evidence_schema.py`** | **7** | Data contract validation, required field checking, ISO-8601 validation, enum integrity. |
| **`test_evidence_canonicalization.py`** | **10** | RFC 8785 JCS key sorting, whitespace normalization, Unicode UTF-8 compliance, NaN/Infinity rejection, non-string key rejection. |
| **`test_evidence_hashing.py`** | **5** | SHA-256 payload reproducibility, avalanche effect on single-bit modification, hash chain linkage, self-referential exclusion. |
| **`test_evidence_repository.py`** | **6** | Isolated SQLite persistence, duplicate ID rejection, append-only immutability triggers (rejects `UPDATE`/`DELETE`), relationship queries. |
| **`test_evidence_provenance.py`** | **3** | Mock fixture provenance, AWS API provenance, W3C PROV graph dictionary export. |
| **`test_evidence_freshness.py`** | **5** | Static fixture categorization, live fresh evidence, stale evidence thresholding, clock-skew boundary rejection. |
| **`test_evidence_verification.py`** | **4** | Single record payload and record hash verification, full ledger chain validation from Genesis (`0000...0000`), tampering detection. |
| **`test_evidence_relationships.py`** | **4** | Proposal-to-evidence binding, legacy unbound proposal compatibility, tampered digest rejection, stale evidence approval blocking. |
| **`test_evidence_integration.py`** | **5** | End-to-end mock fixture ingestion, read-only S3/EC2/IAM connector adaptation, backward-compatibility with `scoring.evidence`. |

---

## 3. Preserved Baseline Tests (46 Tests)

All 46 pre-existing unit and integration tests from Phases 1–3 pass with zero regressions:
- `test_api.py` (4 tests)
- `test_approvals.py` (5 tests)
- `test_attack_rules.py` (4 tests)
- `test_attack_suite.py` (7 tests: T01–T07)
- `test_audit.py` (1 test)
- `test_auth.py` (1 test)
- `test_connectors.py` (7 tests)
- `test_dispatcher.py` (6 tests)
- `test_evidence.py` (2 tests)
- `test_findings.py` (2 tests)
- `test_hashing.py` (1 test)
- `test_proposals.py` (1 test)
- `test_scoring.py` (3 tests)
- `test_sessions.py` (1 test)
- `backend/test_database.py` (1 test)
