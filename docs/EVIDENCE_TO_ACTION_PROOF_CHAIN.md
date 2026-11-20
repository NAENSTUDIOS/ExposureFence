# ExposureFence — 20-Step Evidence-to-Action Proof Chain & Sealed Dossiers

## 1. Executive Summary

In autonomous cloud governance, an AI agent must never be trusted to unilaterally inspect, decide, execute, and verify remediation actions. 

ExposureFence introduces the **Evidence-to-Action Proof Chain** (`backend/governance/`): a mathematically rigorous, 20-step deterministic pipeline that links raw cloud telemetry to verified remediation, sealed in a tamper-evident cryptographic dossier.

Every state transition is validated by a strict 14-state machine, requires out-of-band human authorization, enforces pre-execution revalidation against state drift, and executes independent post-action verification.

---

## 2. The 20-Step Evidence-to-Action Lifecycle

```
[ Finding Ingested ] ──► [ Evidence Bound ] ──► [ Declarative Rules ] ──► [ Contextual Risk ]
         │                        │                         │                        │
      (Step 1)                 (Step 2)                  (Step 3)                 (Step 4)
         │                        │                         │                        │
         └────────────────────────┴─────────────────────────┴────────────────────────┘
                                               │
                                               ▼
                              [ Remediation Plan & Rollback ] (Step 5)
                                               │
                                               ▼
                                  [ Human Approval Gate ] (Step 6)
                                               │
                                               ▼
                              [ Pre-Execution Revalidation ] (Step 7)
                                               │
                                               ▼
                              [ Remediation Execution ] (Step 8)
                                               │
                                               ▼
                              [ Post-Action Verification ] (Step 9)
                                               │
                                               ▼
                              [ Sealed Cryptographic Dossier ] (Step 10-20)
```

### Complete 20-Step Sequence

1. **Finding Identification:** Multi-source finding ingested and normalized into canonical model.
2. **Resource Graph Mapping:** Asset positioned in cloud topology; attack paths discovered.
3. **Evidence Collection:** Raw configuration collected and normalized via RFC 8785 canonical JSON.
4. **Digest Computation:** SHA-256 fingerprint generated for evidence payload.
5. **Ledger Registration:** Evidence recorded in tamper-evident SQLite repository.
6. **Freshness & Integrity Validation:** Evidence verified against known hashes; TTL checked.
7. **Rule Resolution:** Matching declarative security rule loaded from `rules/rules.yaml`.
8. **Rule Evaluation:** Deterministic rule executed; violation conditions evaluated.
9. **Contextual Risk Scoring:** Multi-factor Risk Policy V2 evaluates reachability, IAM, and blast radius.
10. **Proposal Generation:** Remediation proposal synthesized; AI restricted to `PENDING` state.
11. **Rollback Plan Derivation:** Deterministic reverse action and parameters synthesized.
12. **Proof Chain Binding:** All artifacts bound into cryptographic chain record.
13. **Human Review Gate:** Authenticated human operator inspects evidence and proposal.
14. **Human Decision:** Operator signs `APPROVE` or `REJECT` via session cookie + CSRF token.
15. **Pre-Execution Revalidation:** Fresh evidence collected to confirm vulnerability persists (drift check).
16. **Authorized Execution:** Dispatcher executes sanctioned remediation tool.
17. **Telemetry Ingestion:** Fresh post-remediation evidence gathered from the environment.
18. **Independent Post-Action Verification:** Verification engine independently confirms exposure is eliminated.
19. **Dossier Assembly:** All 20 artifacts assembled into a canonical JSON dossier structure.
20. **Cryptographic Sealing:** SHA-256 Merkle root hash generated, logged to audit ledger, and sealed.

---

## 3. The 14-State Proposal Lifecycle State Machine

The state machine (`state_machine.py`) enforces deterministic transitions and prevents race conditions, replay attacks, or unauthorized state jumps:

```
                      ┌───────────────┐
                      │    CREATED    │
                      └───────┬───────┘
                              ▼
                      ┌───────────────┐
                      │    PENDING    │
                      └───┬───────┬───┘
                          │       │
          [ Reject ] ─────┘       └───── [ Approve ]
          ▼                                  ▼
   ┌──────────────┐                  ┌───────────────┐
   │   REJECTED   │                  │   APPROVED    │
   └──────────────┘                  └───────┬───────┘
                                             │
                                             ▼
                                     ┌───────────────┐
                                     │  VALIDATING   │
                                     └───┬───────┬───┘
                                         │       │
                     [ Pre-Check Fails ] ┘       └─ [ Pre-Check Passes ]
                     ▼                              ▼
              ┌──────────────┐              ┌───────────────┐
              │   CANCELED   │              │   EXECUTING   │
              └──────────────┘              └───────┬───────┘
                                                    │
                                                    ▼
                                            ┌───────────────┐
                                            │   EXECUTED    │
                                            └───┬───────┬───┘
                                                │       │
                     [ Verification Fails ] ────┘       └─ [ Verification Passes ]
                     ▼                                     ▼
              ┌──────────────┐                     ┌───────────────┐
              │  ROLLBACK_*  │                     │   VERIFIED    │
              └──────────────┘                     └───────┬───────┘
                                                           │
                                                           ▼
                                                   ┌───────────────┐
                                                   │    SEALED     │
                                                   └───────────────┘
```

### Complete State Catalog (`ProposalLifecycleState`)
- `CREATED`: Initial telemetry ingestion.
- `EVIDENCE_COLLECTED`: Evidence recorded in ledger.
- `EVALUATED`: Declarative rules and risk engine evaluated.
- `PENDING`: Proposal queued for human decision.
- `APPROVED`: Authenticated operator approved action.
- `REJECTED`: Authenticated operator rejected action.
- `VALIDATING`: Pre-execution drift revalidation in progress.
- `EXECUTING`: Approved action currently running.
- `EXECUTED`: Action executed; awaiting ground-truth verification.
- `VERIFIED`: Independent verification confirmed fix.
- `ROLLBACK_PENDING`: Verification failed; rollback initiated.
- `ROLLED_BACK`: Reverse action completed successfully.
- `FAILED`: Execution or verification encountered fatal error.
- `CANCELED`: Pre-execution validation detected state drift; action aborted.

---

## 4. Key Security Invariants

### 4.1 AI Agent Execution Ceiling
The AI agent is structurally incapable of setting any state beyond `PENDING`. Any attempt by an LLM prompt to transition to `APPROVED` or `EXECUTED` raises an unhandled `PermissionError` (verified in `T05`).

### 4.2 Pre-Execution Drift Revalidation (Scenario 4)
Between proposal approval and execution, cloud configuration may change (e.g., an engineer already fixed the bucket, or the resource was deleted). 
Before any tool executes:
1. `validate_pre_execution_state()` queries fresh evidence.
2. If the vulnerability is no longer present, execution is aborted, and the proposal transitions directly to `CANCELED`.
3. This prevents duplicate fixes, race conditions, and catastrophic unintended overwrites.

### 4.3 Deterministic Rollback Plans (`rollback.py`)
Every proposal automatically generates a verified reverse action:
- `enable_s3_block_public_access` $\to$ `disable_s3_block_public_access` (or restore previous ACL/policy).
- `revoke_security_group_ingress` $\to$ `authorize_security_group_ingress` (with exact previous IP ranges and ports).

### 4.4 Independent Post-Action Verifier (`verifier.py`)
The system does not accept agent statements like *"I have remediated the issue"*. The `IndependentPostActionVerifier` independently fetches ground-truth telemetry from the resource and re-runs the declarative rule. Only if the rule evaluates to `PASS` does the proposal reach `VERIFIED`.

---

## 5. Sealed Dossier Cryptography (`dossier.py`)

When a proof chain reaches its terminal verified state, `DossierGenerator.assemble_dossier()` packages all 20 artifacts:
- Finding metadata and source signatures.
- Pre-remediation evidence and payload SHA-256 digest.
- Declarative rule definition and rule-set hash.
- Risk policy version and contextual score breakdown.
- Authenticated human approver ID and session signature.
- Remediation tool dispatch record.
- Post-remediation evidence and verification result.
- Rollback plan digest.

The dossier is serialized using **RFC 8785 canonical JSON** and sealed with a master **Dossier Root Hash**:

$$\text{Dossier Root Hash} = \text{SHA-256}(\text{Canonical JSON}(\text{Dossier Artifacts}))$$

The root hash is logged to the tamper-evident audit ledger and verified by third-party auditors without revealing raw proprietary secrets.
