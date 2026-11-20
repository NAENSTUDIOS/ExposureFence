# ExposureFence — Before and After Engineering Analysis

This document provides a technical comparison between traditional AI security paradigms and the **ExposureFence "Rules as Tests"** framework, as well as a record of repository enhancements achieved during the implementation hardening phase.

---

## 1. Industry Paradigm Contrast: Standard AI Tools vs. ExposureFence

| Security Vector | Standard LLM Security Tool | ExposureFence — Rules as Tests |
| :--- | :--- | :--- |
| **Enforcement Layer** | **Conversational:** Relies on system prompt instructions and model refusals (*"I cannot modify infrastructure"*). | **Architectural:** Server-side dispatcher whitelist and deterministic execution barriers. The model physically cannot execute writes. |
| **Proof of Security** | **Output Text:** Evaluated by checking if the model output text contains refusal keywords. | **Cryptographic Proof:** Verifies zero cloud mutations in audit log, unchanged fixture SHA-256 digests, and tamper-evident hash chaining. |
| **Tool Execution Authority** | **Autonomous Agent:** The LLM directly invokes execution tools or APIs if provided with credentials. | **Controlled Handoff:** The LLM can only suggest a `PENDING` proposal via `propose_fix`. Direct execution does not exist. |
| **Human-in-the-Loop** | **Chat Approval:** Operator says *"approved"* in conversational Slack/web chat. Vulnerable to prompt injection. | **Out-of-Band Governance:** State transitions require an authenticated session cookie and CSRF token via an isolated console. |
| **Data Integrity** | **Implicit Trust:** Assumes cloud metadata (bucket policies, tags, security group descriptions) is trusted. | **Zero-Trust Fixtures:** Metadata is treated strictly as passive data. Embedded adversarial strings cannot hijack the parser. |
| **Remediation Control** | **Generated Shell/Terraform:** LLM writes custom scripts; high hallucination and disruption risk. | **Deterministic Mapping:** Remediation actions are strictly bound to predefined, cryptographically vetted templates. |

---

## 2. Repository Development Record (Before vs. After Implementation)

| Component | Initial Repository Baseline | Hardened Implementation State |
| :--- | :--- | :--- |
| **Amazon Bedrock AgentCore** | Offline JSON schema draft only (`harness_config.json`). No Boto3 client or execution code. | **Fully Implemented Boto3 Client (`agent/agentcore_client.py`):** 12-step Converse streaming handoff loop, strict 3-tool allowlist, and deployment automation (`agent/deploy.py`). |
| **Tool Dispatcher Handoff** | Standalone Python module (`dispatcher.py`). No integration with Bedrock streaming events. | **Bidirectional Tool Handoff:** Captures `toolUse` chunks, routes through dispatcher, and returns structured `toolResult` to Bedrock session. |
| **Live Adversarial Testing** | Markdown specification only (`tests/live/test_specs.md`). Zero executable live tests. | **8 Executable Live Tests (`tests/live/test_agentcore_attacks.py`):** 1 positive functional analysis + 7 live attack vectors with independent invariant checks. |
| **Security Operations Console** | 7 offline tabs; no interaction with AI model or live deployment status. | **AgentCore Console (8th Tab):** Live AWS connection telemetry, interactive model chat with inline tool tracking, and live test runner. |
| **Authentication & Secrets** | Hardcoded default password in server source code; sessions lacked TTL. | **Production-Hardened Auth (`backend/auth.py`, `backend/session_store.py`):** Requires Bcrypt hash in env, returns False if unconfigured, enforces 1-hour session TTL, HttpOnly cookies, SameSite=Strict, CSRF tokens. |
| **Configuration Template** | `.env.example` was 0 bytes (empty stub). | **Fully Documented Template:** Details `EXPOSUREFENCE_DATA_MODE`, AWS region, model ID, harness ARN, admin auth hashes, and localhost binding. |
| **AWS Connectors (Phase 3)** | Mock fixtures only; no live AWS inspection capability. | **Read-Only AWS Connectors (`backend/connectors/`):** Built non-mutating Boto3 connectors for S3, EC2, and IAM with zero-mutation invariant, Botocore Stubber unit tests, and SHA-256 normalized evidence. |
| **Test Suite Coverage** | 38 passing offline tests. | **46 Passing Offline Tests (100%):** Added AgentCore client telemetry, connector unit tests, and security verification. |
| **AWS Integration Delta** | Undocumented mock vs live delta. | **Explicit Data Mode Architecture:** Transparent `EXPOSUREFENCE_DATA_MODE` ('mock' default vs 'aws' read-only), surfaced clearly in console header and summary API. |
