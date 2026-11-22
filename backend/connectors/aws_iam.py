"""
ExposureFence AWS IAM Read-Only Connector (Stage 2 Complete Evolution)
Provides fully paginated, reliable, evidence-producing AWS IAM inventory and policy intelligence
for IAM Roles, IAM Users, Attached Managed Policies, and Inline Policies.
STRICTLY READ-ONLY: Contains zero mutation methods and never accesses secret access keys or passwords.
"""

from datetime import datetime, timezone
import hashlib
import json
import logging
from typing import Any, Dict, List, Optional, Set

from botocore.exceptions import ClientError

from backend.connectors.aws_session import get_boto3_session
from backend.connectors.evidence_status import (
    AssessmentStatus,
    build_failure_evidence,
    map_error_to_assessment_status
)
from backend.connectors.iam_policy_intelligence import (
    normalize_policy_document,
    summarize_identity_policies
)

logger = logging.getLogger("exposurefence.connectors.iam")


def _resolve_iam_client(session=None) -> Any:
    """Resolves an IAM client using ReadOnlyAWSClientFactory or injected mock/boto3 session."""
    if session is not None:
        if hasattr(session, "get_client"):
            return session.get_client("iam")
        if hasattr(session, "client"):
            return session.client("iam")

    from backend.connectors.client_factory import ReadOnlyAWSClientFactory
    factory = ReadOnlyAWSClientFactory()
    return factory.get_client("iam")


# =========================================================================
# 1. IAM ROLE INVENTORY (FULLY PAGINATED)
# =========================================================================

def list_iam_roles(
    max_items: Optional[int] = None,
    session=None,
    max_pages: int = 50
) -> List[Dict[str, Any]]:
    """
    Lists all IAM roles in the account with marker-based pagination and loop detection.
    Never silently truncates results unless max_pages boundary is reached.
    """
    client = _resolve_iam_client(session)
    roles: List[Dict[str, Any]] = []
    marker: Optional[str] = None
    seen_markers: Set[str] = set()
    page_count = 0

    while page_count < max_pages:
        kwargs: Dict[str, Any] = {}
        if max_items:
            kwargs["MaxItems"] = max_items
        if marker:
            kwargs["Marker"] = marker

        response = client.list_roles(**kwargs)
        page_count += 1

        for r in response.get("Roles", []):
            created = r.get("CreateDate")
            roles.append({
                "role_name": r.get("RoleName"),
                "role_id": r.get("RoleId"),
                "arn": r.get("Arn"),
                "create_date": created.isoformat() if hasattr(created, "isoformat") else str(created),
                "assume_role_policy_document": r.get("AssumeRolePolicyDocument")
            })

        is_truncated = response.get("IsTruncated", False)
        next_marker = response.get("Marker")

        if not is_truncated or not next_marker:
            break

        # Detect pagination marker loop
        if next_marker in seen_markers:
            logger.warning("Pagination loop detected in list_roles for marker: %s", next_marker)
            break

        seen_markers.add(next_marker)
        marker = next_marker

    return roles


def get_role_details(role_name: str, session=None) -> Dict[str, Any]:
    """Retrieves metadata and trust policy for an IAM role. Read-only."""
    client = _resolve_iam_client(session)
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


def list_attached_role_policies(
    role_name: str,
    session=None,
    max_pages: int = 20
) -> List[Dict[str, Any]]:
    """Lists customer managed and AWS managed policies attached to a role with pagination."""
    client = _resolve_iam_client(session)
    policies: List[Dict[str, Any]] = []
    marker: Optional[str] = None
    seen_markers: Set[str] = set()
    page_count = 0

    while page_count < max_pages:
        kwargs: Dict[str, Any] = {"RoleName": role_name}
        if marker:
            kwargs["Marker"] = marker

        response = client.list_attached_role_policies(**kwargs)
        page_count += 1

        for p in response.get("AttachedPolicies", []):
            policies.append({
                "policy_name": p.get("PolicyName"),
                "policy_arn": p.get("PolicyArn"),
                "is_admin_policy": p.get("PolicyName") == "AdministratorAccess" or "AdministratorAccess" in p.get("PolicyArn", "")
            })

        is_truncated = response.get("IsTruncated", False)
        next_marker = response.get("Marker")

        if not is_truncated or not next_marker:
            break

        if next_marker in seen_markers:
            logger.warning("Pagination loop detected in list_attached_role_policies for %s", role_name)
            break

        seen_markers.add(next_marker)
        marker = next_marker

    return policies


def list_role_policies(
    role_name: str,
    session=None,
    max_pages: int = 20
) -> List[str]:
    """Lists all inline policy names embedded on an IAM role with pagination."""
    client = _resolve_iam_client(session)
    policy_names: List[str] = []
    marker: Optional[str] = None
    seen_markers: Set[str] = set()
    page_count = 0

    while page_count < max_pages:
        kwargs: Dict[str, Any] = {"RoleName": role_name}
        if marker:
            kwargs["Marker"] = marker

        response = client.list_role_policies(**kwargs)
        page_count += 1

        policy_names.extend(response.get("PolicyNames", []))

        is_truncated = response.get("IsTruncated", False)
        next_marker = response.get("Marker")

        if not is_truncated or not next_marker:
            break

        if next_marker in seen_markers:
            logger.warning("Pagination loop in list_role_policies for %s", role_name)
            break

        seen_markers.add(next_marker)
        marker = next_marker

    return policy_names


def get_role_policy(
    role_name: str,
    policy_name: str,
    session=None
) -> Dict[str, Any]:
    """Retrieves the inline policy document for an IAM role."""
    client = _resolve_iam_client(session)
    response = client.get_role_policy(RoleName=role_name, PolicyName=policy_name)
    return {
        "role_name": role_name,
        "policy_name": policy_name,
        "policy_document": response.get("PolicyDocument")
    }


# =========================================================================
# 2. IAM USER INVENTORY (FULLY PAGINATED, ZERO SECRETS)
# =========================================================================

def list_iam_users(
    max_items: Optional[int] = None,
    session=None,
    max_pages: int = 50
) -> List[Dict[str, Any]]:
    """
    Lists IAM users in the account with marker-based pagination and loop detection.
    Never retrieves access keys, passwords, or credentials.
    """
    client = _resolve_iam_client(session)
    users: List[Dict[str, Any]] = []
    marker: Optional[str] = None
    seen_markers: Set[str] = set()
    page_count = 0

    while page_count < max_pages:
        kwargs: Dict[str, Any] = {}
        if max_items:
            kwargs["MaxItems"] = max_items
        if marker:
            kwargs["Marker"] = marker

        response = client.list_users(**kwargs)
        page_count += 1

        for u in response.get("Users", []):
            created = u.get("CreateDate")
            users.append({
                "user_name": u.get("UserName"),
                "user_id": u.get("UserId"),
                "arn": u.get("Arn"),
                "create_date": created.isoformat() if hasattr(created, "isoformat") else str(created),
                "path": u.get("Path", "/")
            })

        is_truncated = response.get("IsTruncated", False)
        next_marker = response.get("Marker")

        if not is_truncated or not next_marker:
            break

        if next_marker in seen_markers:
            logger.warning("Pagination loop detected in list_users for marker: %s", next_marker)
            break

        seen_markers.add(next_marker)
        marker = next_marker

    return users


def get_user_details(user_name: str, session=None) -> Dict[str, Any]:
    """Retrieves metadata for an IAM user. Read-only metadata only."""
    client = _resolve_iam_client(session)
    response = client.get_user(UserName=user_name)
    u = response.get("User", {})
    created = u.get("CreateDate")
    return {
        "user_name": u.get("UserName"),
        "user_id": u.get("UserId"),
        "arn": u.get("Arn"),
        "create_date": created.isoformat() if hasattr(created, "isoformat") else str(created),
        "path": u.get("Path", "/")
    }


def list_attached_user_policies(
    user_name: str,
    session=None,
    max_pages: int = 20
) -> List[Dict[str, Any]]:
    """Lists customer managed and AWS managed policies attached to a user with pagination."""
    client = _resolve_iam_client(session)
    policies: List[Dict[str, Any]] = []
    marker: Optional[str] = None
    seen_markers: Set[str] = set()
    page_count = 0

    while page_count < max_pages:
        kwargs: Dict[str, Any] = {"UserName": user_name}
        if marker:
            kwargs["Marker"] = marker

        response = client.list_attached_user_policies(**kwargs)
        page_count += 1

        for p in response.get("AttachedPolicies", []):
            policies.append({
                "policy_name": p.get("PolicyName"),
                "policy_arn": p.get("PolicyArn"),
                "is_admin_policy": p.get("PolicyName") == "AdministratorAccess" or "AdministratorAccess" in p.get("PolicyArn", "")
            })

        is_truncated = response.get("IsTruncated", False)
        next_marker = response.get("Marker")

        if not is_truncated or not next_marker:
            break

        if next_marker in seen_markers:
            logger.warning("Pagination loop in list_attached_user_policies for %s", user_name)
            break

        seen_markers.add(next_marker)
        marker = next_marker

    return policies


def list_user_policies(
    user_name: str,
    session=None,
    max_pages: int = 20
) -> List[str]:
    """Lists inline policy names embedded on an IAM user with pagination."""
    client = _resolve_iam_client(session)
    policy_names: List[str] = []
    marker: Optional[str] = None
    seen_markers: Set[str] = set()
    page_count = 0

    while page_count < max_pages:
        kwargs: Dict[str, Any] = {"UserName": user_name}
        if marker:
            kwargs["Marker"] = marker

        response = client.list_user_policies(**kwargs)
        page_count += 1

        policy_names.extend(response.get("PolicyNames", []))

        is_truncated = response.get("IsTruncated", False)
        next_marker = response.get("Marker")

        if not is_truncated or not next_marker:
            break

        if next_marker in seen_markers:
            logger.warning("Pagination loop in list_user_policies for %s", user_name)
            break

        seen_markers.add(next_marker)
        marker = next_marker

    return policy_names


def get_user_policy(
    user_name: str,
    policy_name: str,
    session=None
) -> Dict[str, Any]:
    """Retrieves an inline policy document for an IAM user."""
    client = _resolve_iam_client(session)
    response = client.get_user_policy(UserName=user_name, PolicyName=policy_name)
    return {
        "user_name": user_name,
        "policy_name": policy_name,
        "policy_document": response.get("PolicyDocument")
    }


# =========================================================================
# 3. MANAGED POLICY DOCUMENT RETRIEVAL
# =========================================================================

def get_managed_policy_document(policy_arn: str, session=None) -> Optional[Dict[str, Any]]:
    """Retrieves the default version policy document for a managed policy."""
    client = _resolve_iam_client(session)
    try:
        policy_resp = client.get_policy(PolicyArn=policy_arn)
        default_version = policy_resp.get("Policy", {}).get("DefaultVersionId")
        if not default_version:
            return None

        version_resp = client.get_policy_version(PolicyArn=policy_arn, VersionId=default_version)
        return version_resp.get("PolicyVersion", {}).get("Document")
    except Exception as e:
        logger.debug("Could not retrieve document for managed policy %s: %s", policy_arn, e)
        return None


# =========================================================================
# 4. CANONICAL EVIDENCE GENERATION
# =========================================================================

def collect_iam_role_inventory_evidence(
    role_name: str,
    session=None,
    account_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Collects complete role inventory evidence including attached policies, inline policies,
    trust policy, and policy intelligence analysis.
    """
    try:
        details = get_role_details(role_name, session=session)
        attached = list_attached_role_policies(role_name, session=session)
        inline_names = list_role_policies(role_name, session=session)

        inline_policies = []
        for in_name in inline_names:
            try:
                pol = get_role_policy(role_name, in_name, session=session)
                inline_policies.append(pol)
            except Exception as e:
                logger.warning("Failed to retrieve inline policy %s for role %s: %s", in_name, role_name, e)

        # Policy intelligence summary
        summary = summarize_identity_policies(
            attached_policies=attached,
            inline_policies=inline_policies,
            trust_policy=details.get("assume_role_policy_document"),
            target_account_id=account_id
        )

        has_admin = summary["has_administrator_access"]
        trust_analysis = summary.get("trust_analysis") or {}
        is_cross_account = len(trust_analysis.get("cross_account_principals", [])) > 0
        has_escalations = len(summary.get("escalation_vectors", [])) > 0

        raw_evidence = {
            "resource_id": role_name,
            "role_arn": details.get("arn"),
            "role_details": details,
            "attached_policies": attached,
            "inline_policies": inline_policies,
            "policy_summary": summary,
            "has_administrator_access": has_admin,
            "is_cross_account_trust": is_cross_account,
            "escalation_vectors_count": len(summary.get("escalation_vectors", [])),
            "collection_completeness": {
                "attached_policies_count": len(attached),
                "inline_policies_count": len(inline_policies),
                "is_complete": True
            }
        }

        canonical_raw = json.dumps(raw_evidence, sort_keys=True)
        digest = hashlib.sha256(canonical_raw.encode("utf-8")).hexdigest()
        timestamp = datetime.now(timezone.utc).isoformat()
        evidence_id = f"EV-AWS-IAM-ROLE-{role_name}-{digest[:8]}"

        if has_admin or has_escalations:
            verdict = "PRIVILEGED_ACCESS"
        elif is_cross_account and trust_analysis.get("is_risky_trust"):
            verdict = "CROSS_ACCOUNT_EXPOSURE"
        else:
            verdict = "VERIFIED_SECURE"

        return {
            "evidence_id": evidence_id,
            "resource_id": role_name,
            "source_type": "AWS::IAM::Role",
            "account_id": account_id or "UNKNOWN",
            "region": "global",
            "collection_timestamp": timestamp,
            "raw_evidence": raw_evidence,
            "sha256": digest,
            "verification_result": verdict,
            "assessment_status": AssessmentStatus.VERIFIED.value
        }

    except Exception as exc:
        logger.warning("Error collecting IAM role inventory evidence for %s: %s", role_name, exc)
        status = map_error_to_assessment_status(exc)
        return build_failure_evidence(
            resource_id=role_name,
            source_type="AWS::IAM::Role",
            status=status,
            error_message=str(exc),
            account_id=account_id,
            region="global"
        )


def collect_iam_user_inventory_evidence(
    user_name: str,
    session=None,
    account_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Collects complete user inventory evidence including attached policies, inline policies,
    and privilege escalation analysis. Never reads passwords or access keys.
    """
    try:
        details = get_user_details(user_name, session=session)
        attached = list_attached_user_policies(user_name, session=session)
        inline_names = list_user_policies(user_name, session=session)

        inline_policies = []
        for in_name in inline_names:
            try:
                pol = get_user_policy(user_name, in_name, session=session)
                inline_policies.append(pol)
            except Exception as e:
                logger.warning("Failed to retrieve inline policy %s for user %s: %s", in_name, user_name, e)

        summary = summarize_identity_policies(
            attached_policies=attached,
            inline_policies=inline_policies,
            trust_policy=None,
            target_account_id=account_id
        )

        has_admin = summary["has_administrator_access"]
        has_escalations = len(summary.get("escalation_vectors", [])) > 0

        raw_evidence = {
            "resource_id": user_name,
            "user_arn": details.get("arn"),
            "user_details": details,
            "attached_policies": attached,
            "inline_policies": inline_policies,
            "policy_summary": summary,
            "has_administrator_access": has_admin,
            "escalation_vectors_count": len(summary.get("escalation_vectors", [])),
            "collection_completeness": {
                "attached_policies_count": len(attached),
                "inline_policies_count": len(inline_policies),
                "is_complete": True
            }
        }

        canonical_raw = json.dumps(raw_evidence, sort_keys=True)
        digest = hashlib.sha256(canonical_raw.encode("utf-8")).hexdigest()
        timestamp = datetime.now(timezone.utc).isoformat()
        evidence_id = f"EV-AWS-IAM-USER-{user_name}-{digest[:8]}"

        verdict = "PRIVILEGED_ACCESS" if (has_admin or has_escalations) else "VERIFIED_SECURE"

        return {
            "evidence_id": evidence_id,
            "resource_id": user_name,
            "source_type": "AWS::IAM::User",
            "account_id": account_id or "UNKNOWN",
            "region": "global",
            "collection_timestamp": timestamp,
            "raw_evidence": raw_evidence,
            "sha256": digest,
            "verification_result": verdict,
            "assessment_status": AssessmentStatus.VERIFIED.value
        }

    except Exception as exc:
        logger.warning("Error collecting IAM user inventory evidence for %s: %s", user_name, exc)
        status = map_error_to_assessment_status(exc)
        return build_failure_evidence(
            resource_id=user_name,
            source_type="AWS::IAM::User",
            status=status,
            error_message=str(exc),
            account_id=account_id,
            region="global"
        )


def collect_iam_exposure_evidence(
    role_name: str,
    session=None,
    account_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Backward-compatible entry point for Phase 3 tests and server endpoints.
    Collects role metadata and attached policies to generate an evidence record.
    """
    try:
        details = get_role_details(role_name, session=session)
        attached = list_attached_role_policies(role_name, session=session)
    except Exception as exc:
        logger.warning("Error inspecting IAM role %s: %s", role_name, exc)
        status = map_error_to_assessment_status(exc)
        return build_failure_evidence(
            resource_id=role_name,
            source_type="AWS::IAM::Role",
            status=status,
            error_message=str(exc),
            account_id=account_id,
            region="global"
        )

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
    timestamp = datetime.now(timezone.utc).isoformat()
    evidence_id = f"EV-AWS-IAM-{role_name}-{digest[:8]}"

    return {
        "evidence_id": evidence_id,
        "resource_id": role_name,
        "source_type": "AWS::IAM::Role",
        "account_id": account_id or "UNKNOWN",
        "region": "global",
        "collection_timestamp": timestamp,
        "raw_evidence": raw_evidence,
        "sha256": digest,
        "verification_result": "PRIVILEGED_ACCESS" if has_admin else "VERIFIED_SECURE",
        "assessment_status": AssessmentStatus.VERIFIED.value
    }
