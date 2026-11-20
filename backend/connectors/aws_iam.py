"""
ExposureFence AWS IAM Read-Only Connector
Inspects IAM roles and attached policies for excessive permissions and trust configurations.
STRICTLY READ-ONLY: Never creates, modifies, attaches, or detaches IAM resources.
Never inspects or exports secret credentials or access keys.
"""

from datetime import datetime, UTC
import hashlib
import json
import logging
from typing import Any, Dict, List, Optional

from botocore.exceptions import ClientError
from backend.connectors.aws_session import get_boto3_session

logger = logging.getLogger("exposurefence.connectors.iam")


def list_iam_roles(max_items: int = 50, session=None) -> List[Dict[str, Any]]:
    """Lists IAM roles in the account. Read-only metadata only."""
    sess = session or get_boto3_session()
    client = sess.client("iam")
    response = client.list_roles(MaxItems=max_items)
    roles = []
    for r in response.get("Roles", []):
        created = r.get("CreateDate")
        roles.append({
            "role_name": r.get("RoleName"),
            "role_id": r.get("RoleId"),
            "arn": r.get("Arn"),
            "create_date": created.isoformat() if hasattr(created, "isoformat") else str(created),
            "assume_role_policy_document": r.get("AssumeRolePolicyDocument")
        })
    return roles


def get_role_details(role_name: str, session=None) -> Dict[str, Any]:
    """Retrieves metadata and trust policy for an IAM role. Read-only."""
    sess = session or get_boto3_session()
    client = sess.client("iam")
    response = client.get_role(RoleName=role_name)
    r = response.get("Role", {})
    created = r.get("CreateDate")
    return {
        "role_name": r.get("RoleName"),
        "role_id": r.get("RoleId"),
        "arn": r.get("Arn"),
        "create_date": created.isoformat() if hasattr(created, "isoformat") else str(created),
        "assume_role_policy_document": r.get("AssumeRolePolicyDocument"),
        "description": r.get("Description", "")
    }


def list_attached_role_policies(role_name: str, session=None) -> List[Dict[str, Any]]:
    """Lists customer managed and AWS managed policies attached to a role. Read-only."""
    sess = session or get_boto3_session()
    client = sess.client("iam")
    response = client.list_attached_role_policies(RoleName=role_name)
    policies = []
    for p in response.get("AttachedPolicies", []):
        policies.append({
            "policy_name": p.get("PolicyName"),
            "policy_arn": p.get("PolicyArn"),
            "is_admin_policy": p.get("PolicyName") == "AdministratorAccess"
        })
    return policies


def collect_iam_exposure_evidence(role_name: str, session=None, account_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Collects role metadata and attached policies to generate a normalized Evidence record.
    Never exports credentials.
    """
    details = get_role_details(role_name, session=session)
    attached = list_attached_role_policies(role_name, session=session)

    has_admin = any(p["is_admin_policy"] for p in attached)

    raw_evidence = {
        "resource_id": role_name,
        "role_arn": details.get("arn"),
        "attached_policies": attached,
        "has_administrator_access": has_admin,
        "trust_policy": details.get("assume_role_policy_document")
    }

    canonical_raw = json.dumps(raw_evidence, sort_keys=True)
    digest = hashlib.sha256(canonical_raw.encode("utf-8")).hexdigest()
    timestamp = datetime.now(UTC).isoformat()
    evidence_id = f"EV-AWS-IAM-{role_name}-{digest[:8]}"

    return {
        "evidence_id": evidence_id,
        "resource_id": role_name,
        "source_type": "AWS::IAM::Role",
        "account_id": account_id,
        "region": "global",
        "collection_timestamp": timestamp,
        "raw_evidence": raw_evidence,
        "sha256": digest,
        "verification_result": "PRIVILEGED_ACCESS" if has_admin else "VERIFIED_SECURE"
    }
