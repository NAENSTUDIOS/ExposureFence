"""
ExposureFence — Amazon Bedrock AgentCore Deployment Script
Deploys or updates the managed security harness with explicit inline tools and strict tool allowlist.
Strictly conforms to the Amazon Bedrock AgentCore service contract.
"""

import json
import logging
import os
import sys
from typing import Any, Dict, Optional

import boto3
from botocore.exceptions import ClientError

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("exposurefence.deploy")

SYSTEM_PROMPT_PATH = os.path.join(os.path.dirname(__file__), "system_prompt.md")
STATE_FILE_PATH = os.path.join(os.path.dirname(__file__), "harness_state.json")

HARNESS_NAME = "ExposureFenceHarness"
# Active low-cost model supporting ConverseStream and tool calling (avoids EOL Claude 3.5 Sonnet v2)
MODEL_ID = os.getenv("BEDROCK_MODEL_ID", "amazon.nova-lite-v1:0")

# Approved inline tools matching the ExposureFence security kernel
# Tool type is 'inline_function', configuration key is 'inlineFunction'
INLINE_TOOLS = [
    {
        "type": "inline_function",
        "name": "read_mock_s3",
        "config": {
            "inlineFunction": {
                "description": "Read approved synthetic AWS S3 bucket configurations for security analysis. Returns resource ID, public access settings, policy findings, and evidence ID.",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "additionalProperties": False
                }
            }
        }
    },
    {
        "type": "inline_function",
        "name": "read_mock_security_groups",
        "config": {
            "inlineFunction": {
                "description": "Read approved synthetic AWS EC2 security-group ingress rules for security analysis. Returns security-group ID, protocol, port, CIDR, exposure finding, and evidence ID.",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "additionalProperties": False
                }
            }
        }
    },
    {
        "type": "inline_function",
        "name": "propose_fix",
        "config": {
            "inlineFunction": {
                "description": "Submit a safe remediation fix proposal for a validated security finding. Creates a PENDING proposal for human review.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "finding_id": {
                            "type": "string",
                            "description": "The validated finding identifier (e.g. F-S3-001 or F-SG-001)"
                        }
                    },
                    "required": ["finding_id"],
                    "additionalProperties": False
                }
            }
        }
    }
]

# Strict allowlist restricting tool surface
ALLOWED_TOOLS = ["read_mock_s3", "read_mock_security_groups", "propose_fix"]


def load_system_prompt() -> str:
    if os.path.exists(SYSTEM_PROMPT_PATH):
        with open(SYSTEM_PROMPT_PATH, "r", encoding="utf-8") as f:
            return f.read().strip()
    return "You are ExposureFence, an autonomous cloud security analysis agent."


def find_existing_harness(control, harness_name: str) -> Optional[Dict[str, Any]]:
    """Resolves existing harness through documented ListHarnesses API, never guessing IDs."""
    try:
        response = control.list_harnesses()
        for h in response.get("harnesses", []):
            if h.get("harnessName") == harness_name:
                return h
    except Exception as e:
        logger.warning("Could not list harnesses via ListHarnesses: %s", e)
    return None


def validate_payload_against_model(operation_model, payload: Dict[str, Any]):
    """Validates parameters against the installed Botocore service model."""
    allowed_members = set(operation_model.input_shape.members.keys())
    for k in list(payload.keys()):
        if k not in allowed_members:
            logger.warning("Dropping unexpected payload parameter '%s' not in service model", k)
            del payload[k]


def deploy_harness(region: str = "us-east-1", role_arn: str = None) -> Dict[str, Any]:
    session = boto3.Session(region_name=region)
    control = session.client("bedrock-agentcore-control", region_name=region)
    sts = session.client("sts", region_name=region)

    identity = sts.get_caller_identity()
    logger.info("Deploying with AWS Caller: %s (Account: %s)", identity.get("Arn"), identity.get("Account"))

    execution_role = role_arn or os.getenv("AGENTCORE_EXECUTION_ROLE_ARN")
    if not execution_role:
        raise ValueError(
            "AgentCore execution role is not configured. Set AGENTCORE_EXECUTION_ROLE_ARN "
            "or pass role_arn explicitly. Never invent an execution-role ARN."
        )

    system_prompt_text = load_system_prompt()
    # AgentCore requires systemPrompt as a list of text blocks: [{"text": system_prompt}]
    system_prompt_payload = [{"text": system_prompt_text}]

    create_params = {
        "harnessName": HARNESS_NAME,
        "executionRoleArn": execution_role,
        "model": {
            "bedrockModelConfig": {
                "modelId": MODEL_ID,
                "maxTokens": 1000,
                "temperature": 0.0,
                "apiFormat": "converse_stream"
            }
        },
        "systemPrompt": system_prompt_payload,
        "tools": INLINE_TOOLS,
        "allowedTools": ALLOWED_TOOLS,
        "maxIterations": 5,
        "maxTokens": 1000,
        "timeoutSeconds": 60
    }

    validate_payload_against_model(control._service_model.operation_model("CreateHarness"), create_params)

    # Check for existing harness through documented listing first
    existing = find_existing_harness(control, HARNESS_NAME)
    harness = {}

    if existing:
        real_harness_id = existing.get("harnessId")
        logger.info("Found existing harness '%s' with ID: %s. Updating...", HARNESS_NAME, real_harness_id)
        update_params = dict(create_params)
        del update_params["harnessName"]
        update_params["harnessId"] = real_harness_id
        validate_payload_against_model(control._service_model.operation_model("UpdateHarness"), update_params)
        res = control.update_harness(**update_params)
        harness = res.get("harness", {})
    else:
        logger.info("Creating new AgentCore managed harness '%s' in %s...", HARNESS_NAME, region)
        try:
            res = control.create_harness(**create_params)
            harness = res.get("harness", {})
        except ClientError as e:
            err_code = e.response.get("Error", {}).get("Code", "")
            if "Conflict" in err_code or "ResourceAlreadyExists" in err_code:
                # Fallback to search list again
                existing_retry = find_existing_harness(control, HARNESS_NAME)
                if existing_retry:
                    real_harness_id = existing_retry.get("harnessId")
                    update_params = dict(create_params)
                    del update_params["harnessName"]
                    update_params["harnessId"] = real_harness_id
                    res = control.update_harness(**update_params)
                    harness = res.get("harness", {})
                else:
                    raise
            else:
                raise

    actual_arn = harness.get("arn") or harness.get("harnessArn")
    actual_id = harness.get("harnessId")

    state = {
        "harnessArn": actual_arn,
        "harnessId": actual_id,
        "harnessName": harness.get("harnessName", HARNESS_NAME),
        "region": region,
        "modelId": MODEL_ID,
        "executionRoleArn": execution_role,
        "status": harness.get("status", "CREATED")
    }

    with open(STATE_FILE_PATH, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)

    logger.info("Saved verified deployment state to %s (ARN: %s, ID: %s)", STATE_FILE_PATH, actual_arn, actual_id)
    return state


if __name__ == "__main__":
    target_region = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
    target_role = sys.argv[1] if len(sys.argv) > 1 else None

    print("=" * 65)
    print("  EXPOSUREFENCE — AMAZON BEDROCK AGENTCORE HARNESS DEPLOYMENT")
    print(f"  Target Region: {target_region}")
    print(f"  Model ID:      {MODEL_ID}")
    print(f"  Tools:         {', '.join(ALLOWED_TOOLS)}")
    print("=" * 65)

    try:
        result = deploy_harness(region=target_region, role_arn=target_role)
        print("\nDeployment Completed Successfully!")
        print(f"Harness ARN: {result.get('harnessArn')}")
        print(f"Harness ID:  {result.get('harnessId')}")
        print("\nAdd to your environment:")
        print(f"  export AGENTCORE_HARNESS_ARN=\"{result.get('harnessArn')}\"")
    except Exception as exc:
        logger.error("Deployment stopped: %s", exc)
        sys.exit(1)
