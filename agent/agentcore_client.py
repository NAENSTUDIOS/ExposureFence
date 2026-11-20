"""
ExposureFence — Amazon Bedrock AgentCore Client
Handles Bedrock AgentCore invocation, Converse streaming, and the inline-function tool handoff protocol.
Strictly routes all tool calls through the server-side ExposureFence dispatcher.
"""

import json
import logging
import os
import uuid
from typing import Any, Dict, List, Optional, Tuple

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
        """Returns the current AgentCore deployment and connection status."""
        status = {
            "configured_region": self.region_name,
            "harness_arn": self.harness_arn or "NOT_CONFIGURED",
            "aws_credentials_present": False,
            "caller_arn": None,
            "harness_deployed": False,
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
            harness = control.get_harness(harnessId=harness_id)
            status["harness_deployed"] = True
            status["harness_details"] = harness.get("harness", {})
            status["status_message"] = "AgentCore Harness Ready and Deployed"
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
        Executes the 12-step inline-function tool handoff loop with Amazon Bedrock AgentCore.
        """
        if not self.harness_arn:
            raise ValueError("AGENTCORE_HARNESS_ARN is not configured.")

        session_id = runtime_session_id or str(uuid.uuid4())
        allowed = allowed_tools or APPROVED_TOOL_NAMES

        messages = [
            {
                "role": "user",
                "content": [{"text": prompt}]
            }
        ]

        executed_tools: List[Dict[str, Any]] = []
        conversation_history = list(messages)
        final_text = ""
        iterations = 0

        while iterations < self.max_iterations:
            iterations += 1
            logger.info("AgentCore turn %d for session %s", iterations, session_id)

            invoke_args = {
                "harnessArn": self.harness_arn,
                "runtimeSessionId": session_id,
                "messages": conversation_history,
                "allowedTools": allowed
            }

            if tools_override:
                invoke_args["tools"] = tools_override
            if system_prompt:
                invoke_args["systemPrompt"] = system_prompt

            try:
                response = self.runtime.invoke_harness(**invoke_args)
            except (BotoCoreError, ClientError) as e:
                logger.error("InvokeHarness failed: %s", e)
                raise RuntimeError(f"AgentCore InvokeHarness API error: {e}") from e

            stream = response.get("stream")
            if not stream:
                raise RuntimeError("Empty stream returned from InvokeHarness.")

            # Stream processing state
            current_text_blocks = []
            pending_tool_calls: List[Dict[str, Any]] = []
            current_tool_call: Optional[Dict[str, Any]] = None
            stop_reason = None

            for event in stream:
                if "contentBlockStart" in event:
                    start_data = event["contentBlockStart"].get("start", {})
                    if "toolUse" in start_data:
                        tu = start_data["toolUse"]
                        current_tool_call = {
                            "toolUseId": tu.get("toolUseId"),
                            "name": tu.get("name"),
                            "input_str": ""
                        }

                elif "contentBlockDelta" in event:
                    delta = event["contentBlockDelta"].get("delta", {})
                    if "text" in delta:
                        chunk = delta["text"]
                        current_text_blocks.append(chunk)
                    elif "toolUse" in delta and current_tool_call:
                        current_tool_call["input_str"] += delta["toolUse"].get("input", "")

                elif "contentBlockStop" in event:
                    if current_tool_call:
                        pending_tool_calls.append(current_tool_call)
                        current_tool_call = None

                elif "messageStop" in event:
                    stop_reason = event["messageStop"].get("stopReason")

            turn_text = "".join(current_text_blocks).strip()
            if turn_text:
                final_text = turn_text

            # If no tools requested or end_turn reached, finish loop
            if not pending_tool_calls or stop_reason != "tool_use":
                logger.info("Agent completed without further tool calls. Stop reason: %s", stop_reason)
                break

            # Process requested inline tools through ExposureFence dispatcher
            assistant_content = []
            if turn_text:
                assistant_content.append({"text": turn_text})

            tool_result_content = []

            for tool_call in pending_tool_calls:
                tu_id = tool_call["toolUseId"]
                tool_name = tool_call["name"]
                input_str = tool_call["input_str"]

                try:
                    tool_args = json.loads(input_str) if input_str else {}
                except json.JSONDecodeError:
                    tool_args = {}

                assistant_content.append({
                    "toolUse": {
                        "toolUseId": tu_id,
                        "name": tool_name,
                        "input": tool_args
                    }
                })

                # Server-side security check against allowlist
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

                # Execute strictly through existing dispatcher
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

            # Update conversation history with assistant turn and tool results
            conversation_history.append({
                "role": "assistant",
                "content": assistant_content
            })
            conversation_history.append({
                "role": "user",
                "content": tool_result_content
            })

        return {
            "session_id": session_id,
            "turns": iterations,
            "response": final_text,
            "executed_tools": executed_tools,
            "history": conversation_history
        }
