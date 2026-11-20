"""
ExposureFence — Amazon Bedrock AgentCore Client (Phase 6 & 7 Deep Integration)
Handles Bedrock AgentCore managed harness invocations, Converse streaming, and the
12-step inline-function tool handoff loop.
Strictly routes all tool execution through the ExposureFence dispatcher and binds
all actions to the Phase 4 Evidence Ledger and Phase 5 YAML Rules Engine.
"""

import json
import logging
import os
import re
from typing import Any, Dict, List, Optional, Set
import uuid

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from backend.audit import log_event
from backend.dispatcher import ALLOWED_TOOLS, execute

logger = logging.getLogger("exposurefence.agentcore")

APPROVED_TOOL_NAMES = list(ALLOWED_TOOLS.keys())
DEFAULT_MODEL_ID = os.getenv("BEDROCK_MODEL_ID", "amazon.nova-lite-v1:0")

MAX_INPUT_LENGTH = 4000
MAX_OUTPUT_LENGTH = 8000
MAX_TOOL_CALLS_PER_INVOCATION = 10

# Secret scanning regexes for output sanitization
AWS_ACCESS_KEY_REGEX = re.compile(r"\b(?:AKIA|ASIA|AROA|AIDA)[A-Z0-9]{16}\b")
BEARER_TOKEN_REGEX = re.compile(r"Bearer\s+[A-Za-z0-9_\-\.]{20,}", re.IGNORECASE)
SESSION_COOKIE_REGEX = re.compile(r"session_id=[a-f0-9\-]{36}", re.IGNORECASE)


def sanitize_agent_output(text: str) -> str:
    """
    Redacts leaked credentials, tokens, and sensitive session identifiers
    from model responses before returning to callers.
    """
    if not text:
        return ""
    sanitized = AWS_ACCESS_KEY_REGEX.sub("[REDACTED_AWS_KEY]", text)
    sanitized = BEARER_TOKEN_REGEX.sub("Bearer [REDACTED_TOKEN]", sanitized)
    sanitized = SESSION_COOKIE_REGEX.sub("session_id=[REDACTED_SESSION]", sanitized)
    if len(sanitized) > MAX_OUTPUT_LENGTH:
        sanitized = sanitized[:MAX_OUTPUT_LENGTH] + "\n...[OUTPUT TRUNCATED BY SAFETY POLICY]"
    return sanitized


class AgentCoreClient:
    """Client for interacting with Amazon Bedrock AgentCore managed harness."""

    def __init__(
        self,
        region_name: Optional[str] = None,
        harness_arn: Optional[str] = None,
        max_iterations: int = 5,
        runtime_client: Optional[Any] = None,
        session: Optional[Any] = None,
        guardrail_status: Optional[str] = None,
    ):
        self.region_name = region_name or os.getenv("AWS_DEFAULT_REGION", "us-east-1")
        self.harness_arn = harness_arn or os.getenv("AGENTCORE_HARNESS_ARN")
        self.max_iterations = max_iterations
        self._session = session or boto3.Session(region_name=self.region_name)
        self._runtime_client = runtime_client
        self._guardrail_status_override = guardrail_status
        # In-memory session message store for multi-turn conversational isolation
        self._session_conversations: Dict[str, List[Dict[str, Any]]] = {}

    @property
    def runtime(self):
        if self._runtime_client is not None:
            return self._runtime_client
        self._runtime_client = self._session.client("bedrock-agentcore", region_name=self.region_name)
        return self._runtime_client

    def get_status(self) -> Dict[str, Any]:
        """
        Returns the current AgentCore deployment and connection status.
        Truthfully distinguishes NOT CONFIGURED, MOCKED, DEPLOYED, and ACTIVE.
        """
        # Guardrail configuration verification
        # Distinguishes NOT CONFIGURED, CONFIGURED, DEPLOYED, VERIFIED
        guardrail_env = os.getenv("BEDROCK_GUARDRAIL_ID")
        if self._guardrail_status_override:
            guardrail_state = self._guardrail_status_override
        elif not guardrail_env:
            guardrail_state = "NOT CONFIGURED"
        else:
            guardrail_state = "CONFIGURED (Awaiting deployment validation)"

        status = {
            "configured_region": self.region_name,
            "harness_arn": self.harness_arn or "NOT_CONFIGURED",
            "model_id": DEFAULT_MODEL_ID,
            "aws_credentials_present": False,
            "caller_arn": None,
            "harness_deployed": False,
            "harness_status": "NOT_CONFIGURED",
            "status_message": "Awaiting configuration",
            "guardrail_status": guardrail_state,
            "allowed_tools": list(APPROVED_TOOL_NAMES),
            "runtime_available": False,
        }

        # If mocked runtime client was injected, reflect mock status
        if self._runtime_client is not None:
            status["aws_credentials_present"] = True
            status["caller_arn"] = "arn:aws:iam::123456789012:role/MockAgentCoreExecutionRole"
            status["harness_deployed"] = True
            status["harness_status"] = "MOCKED_LOCAL"
            status["runtime_available"] = True
            status["status_message"] = "Mock AgentCore Client Active (Offline Testing Mode)"
            return status

        try:
            sts = self._session.client("sts", region_name=self.region_name)
            identity = sts.get_caller_identity()
            status["aws_credentials_present"] = True
            status["caller_arn"] = identity.get("Arn")
        except Exception as e:
            status["status_message"] = f"AWS Credential check failed: {e}"
            return status

        if not self.harness_arn:
            status["status_message"] = "Harness ARN not configured in environment (AGENTCORE_HARNESS_ARN)"
            return status

        try:
            control = self._session.client("bedrock-agentcore-control", region_name=self.region_name)
            harness_id = self.harness_arn.split("/")[-1]
            response = control.get_harness(harnessId=harness_id)
            harness_data = response.get("harness", {})
            raw_status = harness_data.get("status", "UNKNOWN")
            status["harness_status"] = raw_status
            status["harness_details"] = harness_data

            if raw_status in ("READY", "ACTIVE"):
                status["harness_deployed"] = True
                status["runtime_available"] = True
                status["status_message"] = f"AgentCore Harness Ready and Deployed (Status: {raw_status})"
            else:
                status["harness_deployed"] = False
                status["runtime_available"] = False
                status["status_message"] = f"AgentCore Harness exists but not ready (Status: {raw_status})"

        except Exception as e:
            status["status_message"] = f"Harness verification error: {e}"

        return status

    def invoke(
        self,
        prompt: str,
        runtime_session_id: Optional[str] = None,
        system_prompt: Optional[str] = None,
        tools_override: Optional[List[Dict[str, Any]]] = None,
        allowed_tools: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Executes the official 12-step inline-function tool handoff loop with Amazon Bedrock AgentCore.
        Integrates dispatcher tool execution, evidence verification, and output sanitization.
        """
        if not prompt or not isinstance(prompt, str):
            raise ValueError("Prompt must be a non-empty string.")

        if len(prompt) > MAX_INPUT_LENGTH:
            raise ValueError(f"Prompt length ({len(prompt)}) exceeds maximum permitted length ({MAX_INPUT_LENGTH})")

        if not self.harness_arn and self._runtime_client is None:
            raise ValueError("AGENTCORE_HARNESS_ARN is not configured and no runtime client was injected.")

        session_id = runtime_session_id or str(uuid.uuid4())
        allowed = allowed_tools or APPROVED_TOOL_NAMES

        # Session message history for turn tracking
        if session_id not in self._session_conversations:
            self._session_conversations[session_id] = []

        # Initial turn message
        user_message = {
            "role": "user",
            "content": [{"text": prompt}]
        }
        self._session_conversations[session_id].append(user_message)
        current_messages = [user_message]

        executed_tools: List[Dict[str, Any]] = []
        final_text = ""
        iterations = 0
        total_tool_calls = 0

        while iterations < self.max_iterations:
            iterations += 1
            logger.info("AgentCore turn %d for session %s", iterations, session_id)

            invoke_args = {
                "harnessArn": self.harness_arn or "arn:aws:bedrock-agentcore:us-east-1:123456789012:harness/mock-harness",
                "runtimeSessionId": session_id,
                "messages": current_messages,
                "allowedTools": allowed,
            }

            if tools_override:
                invoke_args["tools"] = tools_override
            if system_prompt:
                invoke_args["systemPrompt"] = system_prompt

            try:
                response = self.runtime.invoke_harness(**invoke_args)
            except (BotoCoreError, ClientError) as e:
                logger.error("InvokeHarness failed on turn %d: %s", iterations, e)
                raise RuntimeError(f"AgentCore InvokeHarness API error: {e}") from e

            stream = response.get("stream")
            if not stream:
                raise RuntimeError("Empty stream returned from InvokeHarness.")

            # Process event stream tracking contentBlockIndex and toolUseId
            current_text_blocks = []
            pending_tool_calls: List[Dict[str, Any]] = []
            active_tool_calls_by_index: Dict[int, Dict[str, Any]] = {}
            seen_tool_use_ids: Set[str] = set()
            stop_reason = None

            for event in stream:
                if "contentBlockStart" in event:
                    cb_index = event["contentBlockStart"].get("contentBlockIndex", 0)
                    start_data = event["contentBlockStart"].get("start", {})
                    if "toolUse" in start_data:
                        tu = start_data["toolUse"]
                        tu_id = tu.get("toolUseId")
                        if not tu_id:
                            raise ValueError(f"Malformed stream: missing toolUseId in contentBlockStart at index {cb_index}")

                        if tu_id in seen_tool_use_ids:
                            raise ValueError(f"Duplicate toolUseId detected: {tu_id}")
                        seen_tool_use_ids.add(tu_id)

                        active_tool_calls_by_index[cb_index] = {
                            "contentBlockIndex": cb_index,
                            "toolUseId": tu_id,
                            "name": tu.get("name"),
                            "input_str": "",
                        }

                elif "contentBlockDelta" in event:
                    cb_index = event["contentBlockDelta"].get("contentBlockIndex", 0)
                    delta = event["contentBlockDelta"].get("delta", {})

                    if "text" in delta:
                        current_text_blocks.append(delta["text"])
                    elif "toolUse" in delta and cb_index in active_tool_calls_by_index:
                        active_tool_calls_by_index[cb_index]["input_str"] += delta["toolUse"].get("input", "")

                elif "contentBlockStop" in event:
                    cb_index = event["contentBlockStop"].get("contentBlockIndex", 0)
                    if cb_index in active_tool_calls_by_index:
                        pending_tool_calls.append(active_tool_calls_by_index.pop(cb_index))

                elif "messageStop" in event:
                    stop_reason = event["messageStop"].get("stopReason")

                elif "validationException" in event:
                    err_detail = event["validationException"].get("message", "Validation exception in stream")
                    raise ValueError(f"AgentCore stream validation error: {err_detail}")

                elif "internalServerException" in event:
                    err_detail = event["internalServerException"].get("message", "Internal server exception in stream")
                    raise RuntimeError(f"AgentCore internal error: {err_detail}")

            turn_text = "".join(current_text_blocks).strip()
            if turn_text:
                final_text = turn_text

            if not pending_tool_calls:
                logger.info("Agent turn completed with no pending tool calls. Stop reason: %s", stop_reason)
                break

            total_tool_calls += len(pending_tool_calls)
            if total_tool_calls > MAX_TOOL_CALLS_PER_INVOCATION:
                raise RuntimeError(
                    f"Tool-call limit exceeded: {total_tool_calls} tool calls exceeds safety cap ({MAX_TOOL_CALLS_PER_INVOCATION})"
                )

            # Process requested inline tools strictly through ExposureFence dispatcher
            tool_result_content = []

            for tool_call in pending_tool_calls:
                tu_id = tool_call["toolUseId"]
                tool_name = tool_call["name"]
                input_str = tool_call["input_str"].strip()

                tool_args = {}
                malformed_json = False
                if input_str:
                    try:
                        tool_args = json.loads(input_str)
                    except json.JSONDecodeError as jde:
                        malformed_json = True
                        logger.warning("Malformed JSON in tool argument stream for %s: %s", tool_name, jde)

                if malformed_json:
                    err_msg = f"Client error: Malformed JSON arguments for tool '{tool_name}'."
                    executed_tools.append({
                        "tool": tool_name,
                        "args": input_str,
                        "status": "ERROR",
                        "error": err_msg,
                    })
                    tool_result_content.append({
                        "toolResult": {
                            "toolUseId": tu_id,
                            "status": "error",
                            "content": [{"text": err_msg}],
                        }
                    })
                    continue

                if tool_name not in allowed or tool_name not in ALLOWED_TOOLS:
                    err_msg = f"Security Policy Violation: Tool '{tool_name}' is not in the approved allowlist."
                    logger.warning(err_msg)
                    executed_tools.append({
                        "tool": tool_name,
                        "args": tool_args,
                        "status": "BLOCKED",
                        "error": err_msg,
                    })
                    tool_result_content.append({
                        "toolResult": {
                            "toolUseId": tu_id,
                            "status": "error",
                            "content": [{"text": err_msg}],
                        }
                    })
                    continue

                try:
                    result = execute(tool_name, **tool_args)
                    executed_tools.append({
                        "tool": tool_name,
                        "args": tool_args,
                        "status": "SUCCESS",
                        "result": result,
                    })
                    tool_result_content.append({
                        "toolResult": {
                            "toolUseId": tu_id,
                            "status": "success",
                            "content": [{"json": result}],
                        }
                    })
                except Exception as e:
                    err_msg = f"Tool execution failed: {e}"
                    logger.warning(err_msg)
                    executed_tools.append({
                        "tool": tool_name,
                        "args": tool_args,
                        "status": "ERROR",
                        "error": str(e),
                    })
                    tool_result_content.append({
                        "toolResult": {
                            "toolUseId": tu_id,
                            "status": "error",
                            "content": [{"text": err_msg}],
                        }
                    })

            continuation_message = {
                "role": "user",
                "content": tool_result_content,
            }
            self._session_conversations[session_id].append(continuation_message)
            current_messages = [continuation_message]

        if iterations >= self.max_iterations and pending_tool_calls:
            raise RuntimeError(f"Excessive tool iterations ({self.max_iterations}) exceeded safety limit.")

        # Sanitize final output from credential/token leakage
        sanitized_response = sanitize_agent_output(final_text)

        # Audit trail integration
        log_event(
            "AGENTCORE_INVOCATION",
            {
                "session_id": session_id,
                "turns": iterations,
                "total_tool_calls": len(executed_tools),
                "model_id": DEFAULT_MODEL_ID,
                "tools": [t["tool"] for t in executed_tools],
                "stop_reason": stop_reason or "completed",
            },
        )

        return {
            "session_id": session_id,
            "turns": iterations,
            "response": sanitized_response,
            "executed_tools": executed_tools,
        }
