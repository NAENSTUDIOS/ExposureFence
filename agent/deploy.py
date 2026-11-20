"""
ExposureFence — Amazon Bedrock AgentCore Deployment Script
Deploys or updates the managed security harness with explicit inline tools and strict tool allowlist.
"""

import json
import logging
import os
import sys
from typing import Any, Dict

import boto3
from botocore.exceptions import ClientError

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("exposurefence.deploy")

SYSTEM_PROMPT_PATH = os.path.join(os.path.dirname(__file__), "system_prompt.md")
STATE_FILE_PATH = os.path.join(os.path.dirname(__file__), "harness_state.json")

HARNESS_NAME = "ExposureFenceHarness"
MODEL_ID = "us.anthropic.claude-3-5-sonnet-20241022-v2:0"

# Approved inline tools matching the ExposureFence security kernel
INLINE_TOOLS = [
    {
        "type": "inlineFunction",
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
        "type": "inlineFunction",
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
        "type": "inlineFunction",
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


def deploy_harness(region: str = "us-east-1", role_arn: str = None) -> Dict[str, Any]:
    session = boto3.Session(region_name=region)
    control = session.client("bedrock-agentcore-control", region_name=region)
    sts = session.client("sts", region_name=region)

    identity = sts.get_caller_identity()
    logger.info("Deploying with AWS Caller: %s (Account: %s)", identity.get("Arn"), identity.get("Account"))

    execution_role = role_arn or os.getenv("AGENTCORE_EXECUTION_ROLE_ARN")
    if not execution_role:
        account_id = identity.get("Account")
        execution_role = f"arn:aws:iam::{account_id}:role/service-role/ExposureFenceAgentCoreRole"
        logger.info("No execution role specified; using default target: %s", execution_role)

    system_prompt = load_system_prompt()

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
        "systemPrompt": system_prompt,
        "tools": INLINE_TOOLS,
        "allowedTools": ALLOWED_TOOLS,
        "maxIterations": 5,
        "maxTokens": 1000,
        "timeoutSeconds": 60
    }

    logger.info("Creating or updating AgentCore managed harness '%s' in %s...", HARNESS_NAME, region)

    try:
        res = control.create_harness(**create_params)
        harness = res.get("harness", {})
        logger.info("Successfully created harness: %s", harness.get("harnessArn"))
    except ClientError as e:
        err_code = e.response.get("Error", {}).get("Code", "")
        if "Conflict" in err_code or "ResourceAlreadyExists" in err_code:
            logger.info("Harness already exists. Updating existing harness...")
            # Retrieve harness ID or list
            harness_id = HARNESS_NAME
            update_params = dict(create_params)
            del update_params["harnessName"]
            update_params["harnessId"] = harness_id
            res = control.update_harness(**update_params)
            harness = res.get("harness", {})
            logger.info("Successfully updated harness: %s", harness.get("harnessArn"))
        else:
            raise

    state = {
        "harnessArn": harness.get("harnessArn"),
        "harnessId": harness.get("harnessId", HARNESS_NAME),
        "region": region,
        "modelId": MODEL_ID,
        "executionRoleArn": execution_role,
        "status": harness.get("status", "DEPLOYED")
    }

    with open(STATE_FILE_PATH, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)

    logger.info("Saved deployment state to %s", STATE_FILE_PATH)
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
        print("\nAdd to your environment:")
        print(f"  export AGENTCORE_HARNESS_ARN=\"{result.get('harnessArn')}\"")
    except Exception as exc:
        logger.error("Deployment failed: %s", exc)
        sys.exit(1)
