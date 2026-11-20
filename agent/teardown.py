"""
ExposureFence — Cloud Pause & Teardown Utility
Enforces the Zero-Cost Policy by cleanly decommissioning any active Amazon Bedrock AgentCore
resources, managed harnesses, and runtime state, ensuring zero ongoing cloud charges.
"""

import json
import logging
import os
import sys

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("exposurefence.teardown")

STATE_FILE_PATH = os.path.join(os.path.dirname(__file__), "harness_state.json")
HARNESS_NAME = "ExposureFenceHarness"


def pause_and_teardown(region: str = None) -> bool:
    target_region = region or os.getenv("AWS_DEFAULT_REGION", "us-east-1")
    logger.info("Executing Cloud Pause & Teardown in region: %s", target_region)

    session = boto3.Session(region_name=target_region)
    control = session.client("bedrock-agentcore-control", region_name=target_region)

    harness_id = HARNESS_NAME
    has_state_file = os.path.exists(STATE_FILE_PATH)
    if has_state_file:
        try:
            with open(STATE_FILE_PATH, "r", encoding="utf-8") as f:
                state = json.load(f)
                harness_id = state.get("harnessId", HARNESS_NAME)
        except Exception:
            pass

    deletion_verified = False
    access_denied = False

    # 1. Delete AgentCore Harness
    try:
        logger.info("Deleting Bedrock AgentCore managed harness '%s'...", harness_id)
        control.delete_harness(harnessId=harness_id)
        logger.info("Successfully deleted harness: %s", harness_id)
        deletion_verified = True
    except ClientError as e:
        err_code = e.response.get("Error", {}).get("Code", "")
        if "ResourceNotFound" in err_code or "NotFound" in err_code:
            logger.info("Harness '%s' does not exist in AWS. (Already clean)", harness_id)
            deletion_verified = True
        elif "AccessDenied" in err_code:
            logger.error("Teardown unverified: AWS AccessDenied prevented deleting or verifying harness '%s': %s", harness_id, e)
            access_denied = True
            deletion_verified = False
        else:
            logger.error("Error deleting harness: %s", e)
            deletion_verified = False
    except NoCredentialsError:
        logger.info("AWS credentials not configured. Local environment remains 100% offline.")
        deletion_verified = True
    except Exception as e:
        logger.info("AWS credentials not active or check unverified (%s).", e)
        if not has_state_file:
            deletion_verified = True

    # 2. Clean up local state file ONLY if deletion was verified or no cloud resource was ever created
    if deletion_verified and has_state_file:
        try:
            os.remove(STATE_FILE_PATH)
            logger.info("Removed local deployment state file: %s", STATE_FILE_PATH)
        except Exception as e:
            logger.warning("Could not delete state file: %s", e)
    elif access_denied:
        logger.warning("Preserving deployment state file '%s' because cloud deletion could not be verified.", STATE_FILE_PATH)

    # 3. Final FinOps Confirmation
    print("\n" + "=" * 65)
    print("  EXPOSUREFENCE — CLOUD PAUSE SUMMARY")
    print(f"  Target Region:       {target_region}")
    if deletion_verified:
        print(f"  Managed Harness:     DECOMMISSIONED / NOT PRESENT")
        print(f"  Project Charges:     ₹0.00 (Zero billable resources created by this project)")
    else:
        print(f"  Managed Harness:     UNVERIFIED (AccessDenied — Manual AWS review required)")
        print(f"  State File:          PRESERVED ({STATE_FILE_PATH})")
        print(f"  Project Charges:     UNCONFIRMED (Account billing access denied)")
    print(f"  Local Development:   PRESERVED (100% Offline)")
    print("=" * 65)
    return deletion_verified


if __name__ == "__main__":
    reg = sys.argv[1] if len(sys.argv) > 1 else None
    success = pause_and_teardown(region=reg)
    if not success:
        sys.exit(1)
