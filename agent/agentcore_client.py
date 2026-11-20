"""
ExposureFence — Amazon Bedrock AgentCore Client
Handles Bedrock AgentCore invocation, Converse streaming, and the inline-function tool handoff protocol.
Strictly routes all tool calls through the server-side ExposureFence dispatcher.
"""

import json
import logging
import os
import uuid
from typing import Any, Dict, List, Optional, Set

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from backend.dispatcher import ALLOWED_TOOLS, execute

logger = logging.getLogger("exposurefence.agentcore")

APPROVED_TOOL_NAMES = list(ALLOWED_TOOLS.keys())


class AgentCoreClient:
    """Client for interacting with Amazon Bedrock AgentCore managed harness."""

    def __init__(
        self,
        region_name: Optional[str] = None,
        harness_arn: Optional[str] = None,
        max_iterations: int = 5
    ):
        self.region_name = region_name or os.getenv("AWS_DEFAULT_REGION", "us-east-1")
        self.harness_arn = harness_arn or os.getenv("AGENTCORE_HARNESS_ARN")
        self.max_iterations = max_iterations
        self._session = boto3.Session(region_name=self.region_name)
        self._runtime_client = None

    @property
    def runtime(self):
        if self._runtime_client is None:
            self._runtime_client = self._session.client("bedrock-agentcore", region_name=self.region_name)
        return self._runtime_client

    def get_status(self) -> Dict[str, Any]:
        """
        Returns the current AgentCore deployment and connection status.
        Harness is considered READY only when actual AWS status is 'READY' or 'ACTIVE'.
        """
        status = {
            "configured_region": self.region_name,
            "harness_arn": self.harness_arn or "NOT_CONFIGURED",
            "aws_credentials_present": False,
            "caller_arn": None,
            "harness_deployed": False,
            "harness_status": "NOT_CONFIGURED",
            "status_message": "Awaiting configuration"
        }

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

            # Harness is READY only when actual AWS status is READY or ACTIVE
            if raw_status in ("READY", "ACTIVE"):
                status["harness_deployed"] = True
                status["status_message"] = f"AgentCore Harness Ready and Deployed (Status: {raw_status})"
            else:
                status["harness_deployed"] = False
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
        allowed_tools: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Executes the official 12-step inline-function tool handoff loop with Amazon Bedrock AgentCore.
        """
        if not self.harness_arn:
            raise ValueError("AGENTCORE_HARNESS_ARN is not configured.")

        session_id = runtime_session_id or str(uuid.uuid4())
        allowed = allowed_tools or APPROVED_TOOL_NAMES

        # Initial turn: send user prompt
        current_messages = [
            {
                "role": "user",
                "content": [{"text": prompt}]
            }
        ]

        executed_tools: List[Dict[str, Any]] = []
        final_text = ""
        iterations = 0

        while iterations < self.max_iterations:
            iterations += 1
            logger.info("AgentCore turn %d for session %s", iterations, session_id)

            invoke_args = {
                "harnessArn": self.harness_arn,
                "runtimeSessionId": session_id,
                "messages": current_messages,
                "allowedTools": allowed
            }

            # Resend tool definitions on continuation calls when supplied as overrides
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

            # Stream processing tracking contentBlockIndex
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
                            "input_str": ""
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

            # If no tools requested or stopReason indicates completion, finish loop
            if not pending_tool_calls:
                logger.info("Agent turn completed with no pending tool calls. Stop reason: %s", stop_reason)
                break

            # Verify that stopReason equals 'tool_use' when tool calls are pending
            if stop_reason != "tool_use":
                logger.warning("Tool calls detected but stream stopReason was '%s' instead of 'tool_use'", stop_reason)

            # Process requested inline tools through ExposureFence dispatcher only
            tool_result_content = []

            for tool_call in pending_tool_calls:
                tu_id = tool_call["toolUseId"]
                tool_name = tool_call["name"]
                input_str = tool_call["input_str"].strip()

                # Validate JSON arguments
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
                        "error": err_msg
                    })
                    tool_result_content.append({
                        "toolResult": {
                            "toolUseId": tu_id,
                            "status": "error",
                            "content": [{"text": err_msg}]
                        }
                    })
                    continue

                # Server-side security check against exact allowlist
                if tool_name not in allowed or tool_name not in ALLOWED_TOOLS:
                    err_msg = f"Security Policy Violation: Tool '{tool_name}' is not in the approved allowlist."
                    logger.warning(err_msg)
                    executed_tools.append({
                        "tool": tool_name,
                        "args": tool_args,
                        "status": "BLOCKED",
                        "error": err_msg
                    })
                    tool_result_content.append({
                        "toolResult": {
                            "toolUseId": tu_id,
                            "status": "error",
                            "content": [{"text": err_msg}]
                        }
                    })
                    continue

                # Execute strictly through existing backend.dispatcher only
                try:
                    result = execute(tool_name, **tool_args)
                    executed_tools.append({
                        "tool": tool_name,
                        "args": tool_args,
                        "status": "SUCCESS",
                        "result": result
                    })
                    tool_result_content.append({
                        "toolResult": {
                            "toolUseId": tu_id,
                            "status": "success",
                            "content": [{"json": result}]
                        }
                    })
                except Exception as e:
                    err_msg = f"Tool execution failed: {e}"
                    logger.warning(err_msg)
                    executed_tools.append({
                        "tool": tool_name,
                        "args": tool_args,
                        "status": "ERROR",
                        "error": str(e)
                    })
                    tool_result_content.append({
                        "toolResult": {
                            "toolUseId": tu_id,
                            "status": "error",
                            "content": [{"text": err_msg}]
                        }
                    })

            # For continuation, send only the matching user toolResult message
            # AgentCore managed harness retains conversation state server-side
            current_messages = [
                {
                    "role": "user",
                    "content": tool_result_content
                }
            ]

        if iterations >= self.max_iterations and pending_tool_calls:
            raise RuntimeError(f"Excessive tool iterations ({self.max_iterations}) exceeded safety limit.")

        return {
            "session_id": session_id,
            "turns": iterations,
            "response": final_text,
            "executed_tools": executed_tools
        }
