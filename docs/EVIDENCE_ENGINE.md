# ExposureFence — Unified Evidence & Provenance Engine (Phase 4)

## 1. Executive Summary

In traditional cloud security scanners, findings are reported as transient JSON outputs: a scanner asserts that a resource is insecure, and downstream workflows implicitly trust that assertion. When AI agents are introduced to recommend remediations, this lack of verifiable evidence creates dangerous failure modes: hallucinated misconfigurations, prompt-injected policy changes, and remediation of stale or non-existent risks.

**ExposureFence rejects implicit trust.**

The **Unified Evidence & Provenance Engine** establishes an immutable, cryptographically verifiable foundation for every security finding, proposal, and human approval decision. It guarantees that:
1. Every finding is mathematically grounded in a canonicalized, SHA-256 hashed evidence snapshot.
2. Every evidence record preserves provenance: who collected it, what activity created it, where it came from, and when it was observed.
3. Every remediation proposal is bound to the exact cryptographic digest of the evidence that justified it.
4. If evidence is altered, forged, or stale, proposal approval is mathematically blocked.

---

## 2. Core Architectural Flow

```
[ Mock Fixtures / AWS Read-Only Connectors ]
                     │
                     ▼
       [ Evidence Collector Layer ]  (backend/evidence/collector.py)
                     │
                     ▼
   [ RFC 8785 Canonicalization & Normalizer ]  (backend/evidence/canonicalization.py)
                     │
                     ▼
       [ SHA-256 Cryptographic Hasher ]  (backend/evidence/hashing.py)
                     │
                     ▼
      [ Immutable SQLite Evidence Ledger ]  (backend/evidence/repository.py)
        - Table: evidence_records (WAL mode, Append-Only Triggers)
        - Tamper-Evident Hash Chain: prev_record_hash -> record_hash
                     │
                     ├──► [ Freshness & Provenance Engine ] (backend/evidence/freshness.py)
                     │
                     ├──► [ Cryptographic Verifier ] (backend/evidence/verifier.py)
                     │
                     ▼
       [ Evidence Relationships Layer ]  (backend/evidence/relationships.py)
        - Binds Evidence to Finding (SUPPORTS)
        - Binds Evidence to Proposal (SUPPORTS + bound_payload_sha256)
                     │
                     ▼
     [ Authenticated Proposal Approval Gate ]  (backend/approvals.py)
        - Rejects approval if bound evidence is tampered
        - Rejects approval if bound evidence is stale
```

---

## 3. The Evidence-to-Action Proof Chain

The Evidence-to-Action Proof Chain links eight distinct stages:

1. **Cloud Observation:** Read-only connector or synthetic fixture reads configuration metadata (never accessing object content or sensitive secrets).
2. **Normalized Evidence Snapshot:** Converted into a versioned `EvidenceRecord` conforming to Evidence Schema v1.0.0.
3. **RFC 8785 Canonicalization:** Payload is normalized and serialized using the JSON Canonicalization Scheme (RFC 8785) to guarantee cross-platform byte reproducibility.
4. **Tamper-Evident Ledger Append:** Record is inserted into SQLite with an immediate transaction. Its `record_hash` binds the canonical payload and the previous record's hash (`0000...0000` for Genesis).
5. **Freshness & Provenance Evaluation:** Record is classified as `STATIC_FIXTURE`, `FRESH`, or `STALE` based on configurable retention limits (e.g. 1 hour for S3, 30 mins for SG).
6. **Proposal Binding:** When the AI agent or governance engine proposes a fix, the proposal is bound to `evidence_id` and snapshots the `payload_sha256`.
7. **Approval Verification Gate:** Before an administrator can approve a proposal, `verify_proposal_evidence_binding()` verifies that the evidence record is intact, the payload digest matches the proposal's snapshot, and the evidence has not expired.
8. **Independent Execution Separation:** Approvals transition status to `APPROVED` in SQLite without giving the agent AWS write permissions.

---

## 4. Key Differentiators

| Capability | Standard Cloud Scanner | ExposureFence Evidence Engine |
| :--- | :--- | :--- |
| **Integrity Proof** | None (Plain JSON output) | RFC 8785 canonical bytes + SHA-256 payload digest |
| **Persistence** | In-memory or transient DB table | Immutable SQLite ledger protected by SQL `BEFORE UPDATE / DELETE` triggers |
| **History Protection**| Can be overwritten or deleted | Sequential SHA-256 hash chaining (`prev_hash` $\to$ `record_hash`) |
| **Provenance** | Scanner name string | W3C PROV-aligned Entity, Activity, Agent, and source attribution |
| **Freshness Handling**| Scans are assumed fresh | Dedicated freshness evaluator distinguishing `STATIC_FIXTURE`, `FRESH`, and `STALE` |
| **Proposal Safety** | Blind remediation | Proposals are cryptographically bound; tampered/stale evidence blocks approval |
