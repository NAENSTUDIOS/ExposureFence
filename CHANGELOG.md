# Changelog

All notable changes to the ExposureFence platform are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0-rc1] - 2026-11-21

### Added
- **Pre-Publication Release Candidate Gate:** Executed full independent validation resulting in 244/244 passing offline tests and 100% security scorecard.
- **Dedicated Demonstration Scenarios:**
  - `scripts/demo_success_scenario.py`: Scenario A demonstrating successful post-action remediation verification, `VERIFIED` state transition, and sealed Merkle evidence dossier.
  - `scripts/demo_failure_scenario.py`: Scenario B demonstrating independent oracle failure detection, configuration drift catching, and `VERIFICATION_FAILED` state transition without false claims.
- **90% Automated Remediation Approval Policy (`AUTO_REMEDIATION_APPROVAL_V1`):**
  - Ten-category deterministic scoring rubric (100 pts).
  - Floating-point boundary verification at 89.99%, 90.00%, and 90.01%.
  - Eight mandatory security override gates that strictly block automation regardless of score.
  - Cryptographic SHA-256 decision binding.
- **ASIVE Adaptive Intelligence Engine (`backend/adaptive/`):**
  - Continuous multi-source observation and normalized event change detection.
  - 9-point impact analysis and deterministic candidate solution ranking.
  - Isolated evaluation sandbox blocking shell escapes and cloud mutations.
  - Adaptive policy guard enforcing human review for sensitive IAM/rule changes.
  - Controlled self-healing and administrator-controlled rollback mechanics.
- **Open-Source Governance & Developer Onboarding:**
  - `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`, `SUPPORT.md`.
  - `docs/DEVELOPER_ONBOARDING.md`, `docs/PUBLIC_FEATURE_STATUS.md`, `docs/OPEN_SOURCE_RELEASE_GUIDE.md`, `docs/LICENSE_SELECTION.md`.
  - GitHub issue templates (`bug_report.md`, `feature_request.md`, `security_inquiry.md`) and pull request template.

### Changed
- **RFC 8785 Evidence Engine:** Updated `requirements.txt` to explicitly declare `rfc8785==0.1.4` for reproducible developer onboarding.
- **Test Baseline Expansion:** Expanded offline test coverage from 213 to 244 passing tests (100% pass rate in 10.27s).
- **Security Operations Console:** Updated Tab 13 with live Adaptive Intelligence metrics, event feeds, and auto-approval evaluation panels.

### Security
- **Strict Role-Based State Transitions:** Enforced that proposal transitions to `APPROVED` or `AUTO_APPROVED_CONDITIONAL` trigger hard `PermissionError` if called with `caller_role="ai_agent"`.
- **Pre-Execution Revalidation:** Enforced that evidence payload digest must match original proposal binding before simulated execution is permitted.
- **Independent Verification Oracle:** Enforced that post-action verification queries ground-truth state directly rather than trusting caller-supplied claims.

---

## [0.9.0] - 2026-11-20

### Added
- **Feature Groups A–N:** Multi-source finding normalizer, cloud asset graph with bounded BFS attack path traversal, contextual risk engine, and Merkle evidence dossiers.
- **Attack-Path Intelligence:** Integration of asset topology with blast-radius choke points.
- **Compliance Mapping:** Dynamic evaluation across CIS AWS v3.0, NIST CSF 2.0, MITRE ATT&CK Cloud, and OWASP LLM 2025.

---

## [0.5.0] - 2026-11-19

### Added
- **Phase 4 Evidence Ledger:** RFC 8785 canonical JSON digests and SQLite-backed append-only evidence repository.
- **Phase 5 Declarative Rules Engine:** Parsing and evaluation of `rules/rules.yaml` with in-tree AST-safe YAML parser.
- **Phase 6 & 7 Bedrock AgentCore & Dispatcher:** 12-step Converse streaming handoff loop and 3-tool allowlist (`read_mock_s3`, `read_mock_security_groups`, `propose_fix`).

---

## [0.1.0] - 2026-11-18

### Added
- Initial project charter, local Security Operations Console, and baseline mock data fixtures.
