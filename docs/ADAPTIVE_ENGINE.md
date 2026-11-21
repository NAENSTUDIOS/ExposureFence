# ExposureFence — Adaptive Security Intelligence & Verified Evolution Engine (ASIVE)

**Platform Subsystem:** ASIVE Continuous Assurance  
**Operating Budget:** \$0.00 / ₹0.00 (Offline-first mock fixtures)  
**Execution Plane:** Sandboxed Simulation & Review Gate  
**Cloud Providers:** AWS (first-class), Azure, GCP, Kubernetes (provider-neutral models)  

---

## 1. Vision & Architecture

The Adaptive Security Intelligence & Verified Evolution Engine (ASIVE) enables ExposureFence to autonomously detect emerging cloud security threats, assess their architectural impact, propose candidate solutions, evaluate them in isolated sandboxes, and evolve platform intelligence safely over time.

```
┌────────────────────────────────────────────────────────┐
│           1. Continuous Observation Engine             │
│   (Cloud Security, CVE / KEV, AI Security, Compliance) │
└──────────────────────────┬─────────────────────────────┘
                           │ Observations Stream
                           ▼
┌────────────────────────────────────────────────────────┐
│           2. Change Detection & Normalization          │
│   (Deduplication, Source Corroboration, Fingerprints)  │
└──────────────────────────┬─────────────────────────────┘
                           │ ChangeEvents
                           ▼
┌────────────────────────────────────────────────────────┐
│              3. Impact Analysis Engine                 │
│   (9-Point Impact Report, Component Dependencies)      │
└──────────────────────────┬─────────────────────────────┘
                           │ Problem Classification
                           ▼
┌────────────────────────────────────────────────────────┐
│          4. Autonomous Solution & Ranking Engine       │
│   (Candidate Formulation, 10-Dimension Ranking Score)  │
└──────────────────────────┬─────────────────────────────┘
                           │ Ranked Solutions
                           ▼
┌────────────────────────────────────────────────────────┐
│        5. Isolated Sandbox & Verified Policy Guard     │
│   (Invariant Checks, 90% Quality Gate, Review Route)   │
└────────────────────────────────────────────────────────┘
```

---

## 2. Five Cooperating Engines

1. **Security Intelligence Engine (`backend/adaptive/observer.py`):**
   Monitors heterogeneous security signals across five categories (Cloud, Vulnerabilities, AI Security, Compliance, Project Health) using validated offline fixtures.
2. **Problem Understanding Engine (`backend/adaptive/impact_analyzer.py` & `problem_classifier.py`):**
   Correlates evidence, identifies root causes versus symptoms, and computes dependency impact across rules, connectors, and tests.
3. **Autonomous Solution Engine (`backend/adaptive/solution_engine.py`):**
   Formulates candidate solutions (rule updates, connector patches, test expansions, local cache rebuilds) and ranks them across 10 evaluation dimensions.
4. **Verification & Governance Engine (`backend/adaptive/sandbox.py` & `policy_guard.py`):**
   Executes candidate solutions inside an isolated sandbox, validates invariants, verifies zero regressions, and enforces the 90% threshold policy gate.
5. **Evolution & Recovery Engine (`backend/adaptive/evolution_manager.py` & `knowledge_registry.py`):**
   Manages lifecycle states, atomic rollback snapshots, and versioned security knowledge.

---

## 3. Governance Boundaries & Non-Negotiable Controls

- **Zero Cloud Mutations:** ASIVE operates strictly in memory and local fixtures. It has zero AWS write permissions.
- **Human-in-the-Loop for Sensitive Code:** Any adaptation touching YAML rules, IAM heuristics, or governance policies transitions to `APPROVED_FOR_REVIEW` and requires authenticated human authorization before code integration.
- **Self-Healing Scope Cap:** Autonomous self-healing is strictly restricted to safe local maintenance (e.g., rebuilding secondary in-memory search caches). It cannot modify cloud infrastructure or security invariants.
