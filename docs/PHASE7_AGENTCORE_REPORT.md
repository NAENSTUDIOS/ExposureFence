# ExposureFence Task Report: Phase 7 — Amazon Bedrock AgentCore Managed Harness Deep Integration

## 1. Executive Summary

- **Task Completed:** Phase 7 — Amazon Bedrock AgentCore Managed Harness Deep Integration (`agent/agentcore_client.py`, `agent/inline_tools.py`, `agent/deploy.py`, `backend/dispatcher.py`).
- **Integration Core:** Connects the 12-step AgentCore Converse streaming handoff protocol directly to the server-side ExposureFence dispatcher, Phase 4 Evidence Ledger, and Phase 5 YAML Rules Engine.
- **Budget Compliance:** **₹0.00 / $0.00 Out-of-Pocket Spend**. Zero live harness deployments, zero paid runtime invocations.
- **Test Metrics:** 139 / 139 offline tests passing (100% pass rate).
- **Tool Allowlist Surface:** Strictly locked to the three approved inline tools (`read_mock_s3`, `read_mock_security_groups`, `propose_fix`).

---

## 2. The 12-Step Inline-Function Tool Handoff Protocol

ExposureFence implements the documented Amazon Bedrock AgentCore inline-function execution flow:

```
[AgentCore Managed Harness]                      [ExposureFence Application]
             │                                                │
             │── (1) contentBlockStart (toolUse: name, id) ──►│
             │── (2) contentBlockDelta (input chunk) ────────►│
             │── (3) contentBlockStop (block complete) ──────►│
             │── (4) messageStop (stopReason: tool_use) ─────►│
             │                                                │
             │                                  [Security Dispatcher]
             │                                  ├── (5) Validate tool allowlist
             │                                  ├── (6) Parse & validate JSON args
             │                                  ├── (7) Check duplicate toolUseId
             │                                  ├── (8) Execute local python tool
             │                                  └── (9) Bind Evidence & Rules
             │                                                │
             │◄── (10) Send toolResult continuation ──────────│
             │── (11) Stream textual explanation ────────────►│
             │── (12) messageStop (stopReason: end_turn) ────►│
```

### Safety Controls in Stream Parsing:
1. **Content-Block Indexing:** Tracks `contentBlockIndex` across multi-tool invocations to prevent input fragment interleaving.
2. **ToolUse ID De-duplication:** Tracks `seen_tool_use_ids`; duplicate toolUseIds trigger immediate rejection.
3. **Malformed JSON Shield:** Unparseable tool inputs return a structured `toolResult` error message rather than crashing the runtime.
4. **Tool-Call Ceiling:** Restricts invocations to a maximum of 10 tool calls per invocation and 5 conversational iterations.
5. **Runtime Session Continuity:** Uses consistent `runtimeSessionId` across continuation turns, preserving managed session memory.

---

## 3. Tool Implementation Deep Integration

### Tool 1: `read_mock_s3`
- Inspects S3 configurations.
- Retrieves / ingests `EvidenceRecord` in the Phase 4 persistent evidence ledger.
- Evaluates declarative YAML rule `SEC-S3-001` (`RuleType.RESOURCE_COMPLIANCE`).
- Returns structured results containing `resource_id`, `evidence_id`, `payload_sha256`, `integrity_status`, `freshness_status`, and `rule_evaluation`.

### Tool 2: `read_mock_security_groups`
- Inspects EC2 security group ingress permissions.
- Retrieves / ingests `EvidenceRecord` in the evidence ledger.
- Evaluates declarative YAML rule `SEC-EC2-001` (checks for `0.0.0.0/0` exposure on port 22).
- Returns structured results with evidence verification and open-port exposure analysis.

### Tool 3: `propose_fix`
- Accepts a validated finding identifier (`F-S3-001` or `F-SG-001`).
- Resolves its existing `EvidenceRecord` from the ledger.
- Asserts that evidence integrity is `VERIFIED` (rejects `INTEGRITY_MISMATCH`).
- Asserts that evidence freshness is NOT `STALE` (rejects stale evidence).
- Confirms rule evaluation confirms the violation.
- Creates an Advanced Evidence-Bound Proposal with:
  - `proposal_id`
  - `finding_id`
  - `resource_id`
  - `remediation`
  - `status: "PENDING"`
  - `evidence_id`
  - `evidence_payload_digest`
  - `rule_id`
  - `rule_version`
  - `rule_set_digest`
  - `remediation_template_id`
  - `remediation_digest`
  - `created_at`
  - `expires_at` (24-hour default TTL)
- Strictly forbids automated execution or self-approval.

---

## 4. Test Verification (Cases A–T)

All 20 integration cases from Section 11 are verified in `tests/offline/test_agent_integration.py`:

| Case | Scenario | Invariant Verified | Result |
| :---: | :--- | :--- | :---: |
| **A** | Positive security investigation | End-to-end tool execution and explanation | **PASS** |
| **B** | S3 evidence retrieval | Verified evidence ID and rule evaluation returned | **PASS** |
| **C** | Security-group evidence retrieval | Open port analysis and rule evaluation returned | **PASS** |
| **D** | Evidence freshness failure | Stale evidence rejected during proposal creation | **PASS** |
| **E** | Evidence digest mismatch | Tampered evidence payload rejected | **PASS** |
| **F** | Invalid rule evaluation | Proposing fix when rule passes is blocked | **PASS** |
| **G** | Missing evidence binding | Proposing fix without evidence is rejected | **PASS** |
| **H** | Expired proposal | Expired proposal blocked from approval | **PASS** |
| **I** | Fake conversational approval | Chat approval attempt rejected by dispatcher | **PASS** |
| **J** | Direct prompt injection | Shell/cmd execution blocked by allowlist | **PASS** |
| **K** | Indirect evidence injection | Fixture injection treated as inert data | **PASS** |
| **L** | Unknown tool request | Unauthorized tool names rejected | **PASS** |
| **M** | Malformed tool JSON | JSON syntax errors handled gracefully | **PASS** |
| **N** | Duplicate toolUseId | Duplicate toolUseId caught in stream | **PASS** |
| **O** | Missing toolUseId | Missing toolUseId caught in stream | **PASS** |
| **P** | Excessive tool calls | Exceeding 10 tool calls halts execution | **PASS** |
| **Q** | Session reuse | Context preserved across matching sessionId | **PASS** |
| **R** | Session isolation | Independent sessions maintain isolated states | **PASS** |
| **S** | Missing AgentCore configuration | Clear error when harness ARN not configured | **PASS** |
| **T** | AgentCore runtime error | Stream validation exception caught and logged | **PASS** |

---

## 5. Live Deployment Status & Blockers

| Requirement | Current Status | Blocker / Reason |
| :--- | :---: | :--- |
| **Local Codebase Integration** | **100% COMPLETE** | Fully verified locally with mock streams and offline tests. |
| **AWS Credentials** | Awaiting Verification | No AWS credentials configured locally. |
| **Promotional Credits** | ₹0 Out-of-Pocket Policy | Must verify active AWS credits before any deployment. |
| **Harness Deployment** | **NOT DEPLOYED** | Deployment script `agent/deploy.py` ready but unexecuted. |
| **Live Attack Tests** | **NOT RUN** | Marked strictly as NOT RUN until cloud harness is provisioned. |
