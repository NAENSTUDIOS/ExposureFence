# Contributing to ExposureFence

Thank you for your interest in contributing to ExposureFence. ExposureFence is an open-source, evidence-driven AWS Cloud Security Governance and Autonomous Response Assurance Platform.

We welcome contributions from cloud security engineers, DevSecOps practitioners, AI safety researchers, and backend developers.

---

## 1. Core Engineering Invariants

Every contribution must honor the core safety and architectural invariants of ExposureFence:

1. **Zero Out-of-Pocket Cost:**
   - Tests and core functionality must run 100% offline using synthetic fixtures or local mocks.
   - Do not introduce dependencies on paid cloud APIs, proprietary services, or mandatory credit cards.

2. **Zero Cloud Mutation Invariant:**
   - External cloud connectors must be mathematically read-only (using only `Describe*`, `Get*`, and `List*` operations).
   - Remediation logic must execute exclusively in simulated offline mode (`SIMULATED_SUCCESS_ZERO_MUTATION`) unless explicitly flagged in controlled environments.

3. **No AI Self-Approval:**
   - Proposal lifecycle state transitions to `APPROVED` or `AUTO_APPROVED_CONDITIONAL` are strictly off-limits to callers with `caller_role="ai_agent"`.
   - Governance authority belongs exclusively to authenticated human approvers (`APPROVER`, `ADMINISTRATOR`) or the deterministic rule evaluator (`POLICY_ENGINE`).

4. **Cryptographic Provenance:**
   - Security evidence must be normalized and hashed using RFC 8785 (JSON Canonicalization Scheme) and SHA-256 before rule evaluation.

---

## 2. Development & Pull Request Workflow

### Step 1: Branching Strategy
- Fork the repository on GitHub.
- Create a dedicated feature branch from `main`:
  ```bash
  git checkout -b feature/your-feature-name
  ```

### Step 2: Local Verification
Before submitting a pull request, ensure all tests and security evaluations pass locally:
```bash
# 1. Run all offline unit and integration tests (must achieve 100% pass)
python -m pytest tests/offline backend/test_database.py -q

# 2. Run the security scorecard verification
python -m backend.evaluate

# 3. Verify demonstration pipelines execute cleanly
python scripts/demo_success_scenario.py
python scripts/demo_failure_scenario.py
```

### Step 3: Coding Standards & Hygiene
- Follow PEP 8 style guidelines.
- Write descriptive docstrings explaining architectural intent and threat model assumptions.
- Add deterministic offline unit tests in `tests/offline/` for every new rule, connector, or feature.
- Ensure all Python files compile cleanly: `python -m compileall backend agent tests scripts`.

### Step 4: Submitting the Pull Request
- Provide a clear summary of changes in your PR description.
- Reference the verified offline test count and duration.
- Confirm that no live cloud mutations or secret credentials are introduced.

---

## 3. Reporting Bugs & Suggesting Features

- **Bug Reports:** Open an issue using the Bug Report template. Please include Python version, operating system, reproduction steps, and full terminal tracebacks.
- **Feature Requests:** Open an issue using the Feature Request template detailing the security motivation, threat model, and proposed implementation.
- **Security Vulnerabilities:** Do NOT open public issues for security vulnerabilities. Follow the reporting procedure in [SECURITY.md](file:///c:/Users/nasir/ExposureFence/SECURITY.md).
