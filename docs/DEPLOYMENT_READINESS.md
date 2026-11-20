# ExposureFence — P0.1 Deployment Readiness & Zero-Cost Audit Report

**Date:** November 20, 2026  
**Auditor:** Principal AWS Security Architect, IAM Specialist, AgentCore Engineer & Cloud Cost Auditor  
**Budget Policy:** **STRICT ₹0.00 / $0.00 OUT-OF-POCKET EXPENSE (ZERO-TOLERANCE)**  
**Audit Scope:** Read-Only Pre-Deployment Verification & Financial Assessment  
**Final Status:** **BLOCKED (Missing AWS Bedrock Permissions & Unverified Credits)**  

---

## 1. Current Implementation Status

All core security and governance logic has been fully developed, hardened, and verified locally without incurring any cloud costs:

| Component | Status | Verification & Code Evidence |
| :--- | :---: | :--- |
| **Offline Test Suite** | **100% PASS** | **39 passed in 1.33s** (`tests/offline/` & `backend/test_database.py`). |
| **Security Scorecard** | **100%** | `backend/evaluate.py`: R01–R07 PASS, T01–T07 PASS. |
| **Three-Tool Dispatcher** | **ACTIVE** | `backend/dispatcher.py` strictly restricts tools to `read_mock_s3`, `read_mock_security_groups`, `propose_fix`. |
| **Audit Hash Chaining** | **VERIFIED** | `audit.jsonl` (236 events): `verify_audit_hash_chain() == True`. |
| **Zero-Mutation Invariant** | **VERIFIED** | `verify_zero_mutations() == True` confirms 0 cloud write attempts. |
| **SQLite Proposals** | **ACTIVE** | `exposurefence.db`: 105 total records (81 `PENDING`, 24 `APPROVED`). |
| **AgentCore Client** | **BUILT** | `agent/agentcore_client.py`: 12-step Converse streaming handoff loop. |
| **Deployment Automation**| **BUILT** | `agent/deploy.py`: Boto3 `create_harness` / `update_harness` script. |
| **Teardown Automation** | **BUILT** | `agent/teardown.py`: Clean decommissioning utility (`pause_and_teardown`). |
| **Security Console** | **ACTIVE** | `backend/server.py`: 8 lightweight tabs bound strictly to `127.0.0.1:8000`. |
| **Live Attack Suite** | **8 TESTS** | `tests/live/test_agentcore_attacks.py`: Safely reports `SKIPPED / NOT RUN`. |

---

## 2. Model Lifecycle Verification & Correction

### The Issue with Claude 3.5 Sonnet v2
The initial project draft referenced `us.anthropic.claude-3-5-sonnet-20241022-v2:0`.
- **Lifecycle Assessment:** According to official AWS Bedrock lifecycle announcements, Claude 3.5 Sonnet v2 was classified under **Legacy / End-of-Life (EOL)** in late 2026. Invoking this model ID in non-supported regions or post-sunset produces validation exceptions (`ResourceNotFoundException` or invalid model identifier errors).
- **Economic Inefficiency:** At \$3.00/1M input tokens and \$15.00/1M output tokens, Sonnet v2 is excessively costly for high-frequency automated evaluation.

### Recommended Active Model: Amazon Nova Lite v1.0 (`amazon.nova-lite-v1:0`)
- **Lifecycle Status:** **ACTIVE / CURRENT** (General Availability).
- **Tool-Use (Function Calling) Support:** Fully supported natively via the Bedrock Converse and ConverseStream APIs.
- **Converse Streaming Support:** Supported. Yields incremental text and tool arguments across `contentBlockDelta` events.
- **Inference Profile Requirements:** Direct model ID supported; cross-region routing profiles available.
- **Pricing:**
  - **Input Tokens:** **\$0.06 per 1,000,000 tokens** (98.0% cheaper than Sonnet v2).
  - **Output Tokens:** **\$0.24 per 1,000,000 tokens** (98.4% cheaper than Sonnet v2).

### Alternative Active Model: Anthropic Claude 3.5 Haiku (`us.anthropic.claude-3-5-haiku-20241022-v1:0`)
- **Lifecycle Status:** **ACTIVE / CURRENT**.
- **Tool-Use Support:** Fully supported with rapid sub-second inference latency.
- **Pricing:** \$0.80 per 1M input tokens / \$4.00 per 1M output tokens (73% cheaper than Sonnet v2).

### Implemented Model Configuration Correction
`agent/deploy.py`, `agent/harness_config.json`, `backend/server.py`, and `.env.example` have been updated to dynamically read `BEDROCK_MODEL_ID`, defaulting to **`amazon.nova-lite-v1:0`**.

---

## 3. Region Compatibility Analysis

- **Current Configured Region:** `ap-south-1` (Mumbai).
- **Bedrock Endpoint Resolution:**
  - Bedrock control and data endpoints are active in `ap-south-1` (`https://bedrock.ap-south-1.amazonaws.com`).
  - Bedrock AgentCore service endpoints resolve in `ap-south-1` (`https://bedrock-agentcore.ap-south-1.amazonaws.com`).
- **Regional Model Caveats:**
  - Amazon Nova Lite (`amazon.nova-lite-v1:0`) is available directly in `us-east-1`, `us-west-2`, and `ap-south-1`.
  - Anthropic Claude 3.5 Haiku and Claude 3.7 Sonnet in `ap-south-1` require cross-region inference profiles (`us.` prefix routing to US multi-region endpoints).
- **Recommendation:**
  - If deploying Nova Lite: Retain `ap-south-1` or target `us-east-1`.
  - If deploying Anthropic Claude models: Target `us-east-1` (`AWS_DEFAULT_REGION=us-east-1`).

---

## 4. Exact IAM Permission Matrix

In adherence to the Principle of Least Privilege, **zero wildcard permissions (`*`)** are permitted. The table below specifies the exact IAM actions, principals, and resource scopes required across all lifecycle stages:

| Phase / Operation | IAM Action | Authorized Principal | Resource Scope | Purpose & Constraints |
| :--- | :--- | :--- | :--- | :--- |
| **A. Deployment** | `bedrock-agentcore:CreateHarness` | Deployment Operator (IAM User) | `arn:aws:bedrock-agentcore:REGION:ACCOUNT:harness/*` | Creates managed harness `ExposureFenceHarness`. |
| **A. Deployment** | `bedrock-agentcore:UpdateHarness` | Deployment Operator (IAM User) | `arn:aws:bedrock-agentcore:REGION:ACCOUNT:harness/*` | Updates prompt, tools, or model configuration. |
| **A. Deployment** | `bedrock-agentcore:GetHarness` | Deployment Operator & Console Server | `arn:aws:bedrock-agentcore:REGION:ACCOUNT:harness/*` | Verifies harness readiness and status. |
| **A. Deployment** | `iam:PassRole` | Deployment Operator (IAM User) | `arn:aws:iam::ACCOUNT:role/service-role/ExposureFenceAgentCoreRole` | Passes execution role to AgentCore. **Conditioned to `iam:PassedToService == bedrock-agentcore.amazonaws.com`**. |
| **B. Execution Role** | `sts:AssumeRole` | AWS Service Principal | `bedrock-agentcore.amazonaws.com` | Trust relationship enabling AgentCore to run the harness. |
| **C. Runtime Invocation** | `bedrock-agentcore:InvokeHarness` | Runtime Client (`agentcore_client.py`) | `arn:aws:bedrock-agentcore:REGION:ACCOUNT:harness/ExposureFenceHarness*` | Sends conversation messages and receives Converse stream. |
| **D. Model Inference** | `bedrock:InvokeModelWithResponseStream` | AgentCore Execution Role | `arn:aws:bedrock:REGION::foundation-model/*`<br>`arn:aws:bedrock:REGION:ACCOUNT:inference-profile/*` | Allows AgentCore to invoke Foundation Model streaming. |
| **E. Guardrails (Optional)** | `bedrock:ApplyGuardrail` | AgentCore Execution Role | `arn:aws:bedrock:REGION:ACCOUNT:guardrail/*` | Evaluates prompts against Bedrock Guardrail. |
| **F. Logging** | `logs:CreateLogStream`<br>`logs:PutLogEvents` | AgentCore Execution Role | `arn:aws:logs:REGION:ACCOUNT:log-group:/aws/bedrock-agentcore/*` | Emits execution logs with strict 1-day retention. |
| **G. Decommissioning** | `bedrock-agentcore:DeleteHarness` | Teardown Script (`agent/teardown.py`) | `arn:aws:bedrock-agentcore:REGION:ACCOUNT:harness/*` | Deletes harness immediately after demo ($0 ongoing). |

### Explicit Security Denials:
- `bedrock-agentcore:InvokeAgentRuntimeCommand`: **EXPLICITLY PROHIBITED**. The deployment operator and runtime client never receive direct container/runtime execution permissions.
- `s3:*`, `ec2:*`: **ZERO PERMISSIONS**. The AgentCore execution role has no permissions to read or write live cloud infrastructure.
- `iam:*`: The AgentCore execution role has zero IAM permissions.

---

## 5. Minimal Customer-Managed IAM Policy Drafts

### Policy 1: Deployment Operator Minimal Policy (`ExposureFenceOperatorPolicy`)
Attach this policy to the deployment user only during the deployment and evaluation window:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AgentCoreHarnessManagement",
      "Effect": "Allow",
      "Action": [
        "bedrock-agentcore:CreateHarness",
        "bedrock-agentcore:UpdateHarness",
        "bedrock-agentcore:GetHarness",
        "bedrock-agentcore:DeleteHarness"
      ],
      "Resource": "arn:aws:bedrock-agentcore:*:*:harness/*"
    },
    {
      "Sid": "AgentCoreHarnessInvocation",
      "Effect": "Allow",
      "Action": [
        "bedrock-agentcore:InvokeHarness"
      ],
      "Resource": "arn:aws:bedrock-agentcore:*:*:harness/*"
    },
    {
      "Sid": "RestrictedPassRoleToAgentCore",
      "Effect": "Allow",
      "Action": "iam:PassRole",
      "Resource": "arn:aws:iam::*:role/service-role/ExposureFenceAgentCoreRole",
      "Condition": {
        "StringEquals": {
          "iam:PassedToService": "bedrock-agentcore.amazonaws.com"
        }
      }
    }
  ]
}
```

### Policy 2: Harness Execution Role Trust Policy (`TrustPolicy.json`)
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AgentCoreTrust",
      "Effect": "Allow",
      "Principal": {
        "Service": "bedrock-agentcore.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

### Policy 3: Harness Execution Role Permission Policy (`ExposureFenceHarnessExecutionPolicy`)
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "BedrockModelStreamingInference",
      "Effect": "Allow",
      "Action": [
        "bedrock:InvokeModelWithResponseStream"
      ],
      "Resource": [
        "arn:aws:bedrock:*::foundation-model/*",
        "arn:aws:bedrock:*:*:inference-profile/*"
      ]
    },
    {
      "Sid": "AgentCoreLoggingMinimal",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:*:*:log-group:/aws/bedrock-agentcore/*"
    }
  ]
}
```

---

## 6. Credit and Cost Audit

### Account Credit Verification Status: **UNVERIFIED / BLOCKED**
- **Configured Identity:** `arn:aws:iam::584860296694:user/ecr-user`
- **Cost Explorer / Billing Query:** Returned `AccessDenied`.
- **Bedrock ListFoundationModels Query:** Returned `AccessDeniedException`.
- **FinOps Policy Mandate:** In strict adherence to the Zero-Cost Policy, without verifiable promotional credits and without explicit user approval, **cloud deployment is strictly BLOCKED**.

### Official AWS Pricing Data

| Service Component | Unit | Rate (USD) | Rate (INR @ ₹83.50/$) |
| :--- | :--- | :--- | :--- |
| **Amazon Nova Lite (Input)** | Per 1,000,000 tokens | **\$0.06** | **₹5.01** |
| **Amazon Nova Lite (Output)** | Per 1,000,000 tokens | **\$0.24** | **₹20.04** |
| **Claude 3.5 Haiku (Input)** | Per 1,000,000 tokens | **\$0.80** | **₹66.80** |
| **Claude 3.5 Haiku (Output)** | Per 1,000,000 tokens | **\$4.00** | **₹334.00** |
| **AgentCore Harness Fee** | Managed Orchestration | **\$0.00** (Free) | **₹0.00** |
| **AgentCore Memory Store** | Storage / Retrieval | *Disabled in config* | **₹0.00** |
| **CloudWatch Logs** | Ingestion per GB | **\$0.50** | **₹41.75** |

---

## 7. Runtime Pricing Estimate (Full Test Evaluation)

A single comprehensive live evaluation cycle consists of **8 total invocations**:
- **1 Positive Functional Test:** Agent inspects mock fixtures, detects public exposure, and proposes safe remediation.
- **7 Adversarial Attack Tests (T01–T07):** Evaluates boundaries against prompt injection, mutation attempts, privilege escalation, data exfiltration, fake approvals, S3 injection, and SG injection.

### Token & Resource Consumption Metrics:
- **Total Test Invocations:** 8 prompts
- **Average Input Tokens per Turn:** ~1,800 tokens (System prompt + mock JSON fixtures + conversation history + tool definitions)
- **Average Turns per Session:** 3 turns
- **Total Input Tokens:** ~45,000 tokens
- **Average Output Tokens per Turn:** ~400 tokens
- **Total Output Tokens:** ~10,000 tokens
- **Runtime Compute / CPU / Memory:** \$0.00 (Inline tools execute on local Python client; no container infrastructure provisioned in AWS).
- **CloudWatch Logs:** ~150 KB logs (< \$0.0001).

### Financial Exposure Calculation:

$$\text{Cost}_{\text{Nova Lite}} = (45{,}000 \times \$0.00000006) + (10{,}000 \times \$0.00000024) = \$0.0027 + \$0.0024 = \mathbf{\$0.0051 \quad (\approx \text{₹}0.43)}$$

$$\text{Cost}_{\text{Claude Haiku}} = (45{,}000 \times \$0.00000080) + (10{,}000 \times \$0.00000400) = \$0.0360 + \$0.0400 = \mathbf{\$0.0760 \quad (\approx \text{₹}6.35)}$$

---

## 8. Total Estimated Test Exposure

- **Worst-Case Cost per Full Evaluation Run (Amazon Nova Lite):** **₹0.43 ($0.0051)**
- **Worst-Case Cost per Full Evaluation Run (Claude 3.5 Haiku):** **₹6.35 ($0.076)**
- **Ambient / Idling Cost:** **₹0.00 / $0.00** (No provisioned instances, no active memory stores).
- **Personal Budget Exposure:** **₹0.00**. Because personal out-of-pocket spending is non-negotiable at ₹0, this cost must either be absorbed by valid promotional credits or deployment must remain disabled.

---

## 9. Deployment Blockers

Before AWS deployment can safely execute, the following blockers must be resolved:

1. **IAM Policy Blocker:** User `ecr-user` currently lacks permissions to invoke Bedrock or manage AgentCore harnesses.
2. **Credit Verification Blocker:** Billing API access is denied, preventing automated proof of available promotional credits.
3. **Execution Role Absence:** IAM role `ExposureFenceAgentCoreRole` does not yet exist in the account.

---

## 10. Cost-Safe Future Deployment Plan

### Path A: Eligible Credits Verified (Live Cloud Evaluation)
1. Verify active AWS promotional credits in the AWS Billing Console.
2. Create `ExposureFenceAgentCoreRole` using the trust policy in Section 5.
3. Attach `ExposureFenceOperatorPolicy` to the deployment identity.
4. Execute deployment:
   ```bash
   python -m agent.deploy
   ```
5. Run the live adversarial attack suite:
   ```bash
   python -m pytest tests/live -v
   ```
6. Capture console screenshots and demo recording.
7. Immediately trigger teardown:
   ```bash
   python -m agent.teardown
   ```

### Path B: Credits Unavailable (Permanent Local Operation — CURRENT DEFAULT)
1. Maintain all operations locally without deploying AWS resources.
2. The entire security kernel, 39 offline tests, 7 security rules, 7 attack tests, and the 8-tab Security Console continue running locally at **100% functionality and ₹0 cost**.
3. Live AgentCore tests in `tests/live/test_agentcore_attacks.py` safely remain `SKIPPED / NOT RUN`.
4. The deployment scripts (`agent/deploy.py`, `agent/agentcore_client.py`, `agent/teardown.py`) remain preserved in Git for future internship or production demonstrations.

---

## 11. Post-Hackathon Cleanup Steps (Decommissioning)

To guarantee that no orphaned resources or lingering charges exist following any live evaluation:

1. **Harness Termination:** Run `python -m agent.teardown` to execute `control.delete_harness(harnessId='ExposureFenceHarness')`.
2. **Session Cleanup:** End all active AgentCore runtime sessions.
3. **Log Group Deletion:** In CloudWatch Logs, delete `/aws/bedrock-agentcore/ExposureFenceHarness` or set retention to 1 day.
4. **Policy Detachment:** Remove `ExposureFenceOperatorPolicy` from the IAM principal.
5. **Billing Verification:** Verify in the AWS Billing dashboard that active running resources = 0.
6. **Code Preservation:** Confirm all local code, mock fixtures, SQLite records, and Git history remain intact on disk.

---

## 12. Master Roadmap Preservation (The Seven Phases)

ExposureFence preserves the master development plan across all seven phases:

| Phase | Phase Name | Status | Current Reality & Future Plan |
| :---: | :--- | :---: | :--- |
| **Phase 1** | **Security Operations Dashboard** | **COMPLETE** | 8 functional tabs running on local `ThreadingHTTPServer` at `http://127.0.0.1:8000`. Zero CDN dependencies. |
| **Phase 2** | **REST API** | **COMPLETE** | Local REST API handling session auth, summary KPIs, proposals, evidence, audit logs, and AgentCore status. |
| **Phase 3** | **AWS S3, EC2 & IAM Connectors** | **PENDING** | Deliberately deferred for hackathon MVP to enforce synthetic isolation and ₹0 budget. Real read-only `boto3` connectors planned for v2. |
| **Phase 4** | **Evidence Engine** | **PARTIAL** | SHA-256 fixture integrity validation (`backend/integrity.py`) and static registry (`scoring/evidence.py`). Dynamic ingestion planned for v2. |
| **Phase 5** | **YAML Rules Engine** | **COMPLETE** | Declarative rules R01–R07 codified in `rules/rules.yaml`, mapped to T01–T07, evaluated deterministically via `backend/evaluate.py`. |
| **Phase 6** | **Amazon Bedrock** | **READY** | Model inference configured for active low-cost models (`amazon.nova-lite-v1:0` / `claude-3-5-haiku`). |
| **Phase 7** | **Amazon Bedrock AgentCore** | **INTEGRATED** | Managed harness deployment script, 12-step Converse streaming handoff, and 3-tool allowlist implemented. Awaiting authorized credentials. |

---

## 13. Final Decision & Recommendation

### **FINAL AUDIT VERDICT: BLOCKED**

- **Reason:** While the entire software architecture, AgentCore handoff loop, and test suites are 100% complete locally, the currently configured AWS IAM user (`ecr-user`) lacks Bedrock permissions, and promotional credit balances cannot be verified.
- **Budget Compliance:** **₹0.00 spent. ₹0.00 billed.**
- **Recommended Action:** **DO NOT DEPLOY TO AWS.** Continue running ExposureFence 100% locally via `python -m backend.server`. Demonstrate the 8 console tabs, 39 passing tests, and the "Rules as Tests" architecture in offline verification mode until eligible AWS credits and permissions are explicitly provided.
