# ExposureFence — Open-Source Release & Publication Guide

**Document Purpose:** Standard operating procedure for verifying, packaging, and publishing open-source releases of ExposureFence.  
**Governing Authority:** Repository Owner (NAENSTUDIOS).  
**Pre-Requisite:** Full completion of pre-publication verification gate.  

---

## 1. Release Governance & Authority Model

All release and publication actions are strictly controlled:
1. **Owner Authority:** No release tag, branch merge into `main`, GitHub Release, or PyPI package may be published without explicit, written authorization from the repository owner.
2. **Zero-Mutation Release Gate:** Releases must pass 100% of offline unit and integration tests, verify all 7 declarative security rules, and confirm zero cloud mutation invariants.

---

## 2. Pre-Release Verification Checklist

Before tagging or publishing any release candidate:

### Quality & Test Invariants
- [ ] Complete offline test suite passes: `pytest tests/offline backend/test_database.py -q` (244/244 passed).
- [ ] Security scorecard passes: `python -m backend.evaluate` (100% score; R01–R07 & T01–T07 passed).
- [ ] End-to-end pipeline executes cleanly: `python scripts/demo_pipeline.py` (15/15 steps verified).
- [ ] Scenario A succeeds: `python scripts/demo_success_scenario.py` (State: `VERIFIED`).
- [ ] Scenario B succeeds: `python scripts/demo_failure_scenario.py` (State: `VERIFICATION_FAILED`).
- [ ] Audit hash chain continuity verified intact: `python -c "from backend.audit import verify_audit_hash_chain; assert verify_audit_hash_chain() is True"`.
- [ ] AST syntax compilation clean across all source trees: `python -m compileall backend agent tests scripts`.

### Security & Supply Chain Checks
- [ ] Secret scan passes: Zero hardcoded AWS keys (`AKIA...`), API tokens, or private certificates committed.
- [ ] Environment file clean: `.env` is gitignored; `.env.example` contains only non-secret placeholders.
- [ ] Third-party dependencies pinned in `requirements.txt`.
- [ ] License attribution documented in `docs/LICENSE_SELECTION.md`.

### Documentation Readiness
- [ ] `README.md` links verified and working.
- [ ] `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`, and `SUPPORT.md` present in root.
- [ ] `CHANGELOG.md` reflects current milestone deliverables.
- [ ] `docs/PUBLIC_FEATURE_STATUS.md` uses accurate, honest verification statuses.
- [ ] `docs/RELEASE_LIMITATIONS.md` transparently documents offline simulation boundaries.

---

## 3. Step-by-Step Release Workflow

### Step 1: Stage and Commit Verification Deliverables
Ensure working directory is clean on `feature/top-tier-platform-evolution`:
```bash
git status
```

### Step 2: Generate Release Checksums
Compute SHA-256 digests of all release assets and source archives for distribution integrity:
```bash
python -c "
import hashlib, os
for f in ['README.md', 'requirements.txt', 'rules/rules.yaml']:
    with open(f, 'rb') as fp:
        print(f'{hashlib.sha256(fp.read()).hexdigest()}  {f}')
"
```

### Step 3: Owner Authorization Checkpoint
Present the Release Candidate Validation Report (`docs/FINAL_RELEASE_VALIDATION.md`) to the repository owner. **Do not proceed beyond this point without explicit confirmation.**

### Step 4: Fast-Forward Merge to `main` (Authorized Only)
Once authorized:
```bash
git checkout main
git merge --ff-only feature/top-tier-platform-evolution
git push origin main
```

### Step 5: Git Tagging & Release Announcement
```bash
git tag -a v1.0.0 -m "ExposureFence Release Candidate 1.0.0 — Open-Source Governance Platform"
git push origin v1.0.0
```

---

## 4. Rollback & Emergency Procedures

If any unexpected regression, supply chain concern, or security vulnerability is detected post-tagging:
1. Immediately revert the tag or merge commit on `main`.
2. Document the issue in `CHANGELOG.md` under a `[Unreleased - Retracted]` section.
3. Conduct root cause analysis in `tests/offline/` and add regression tests before re-tagging.
