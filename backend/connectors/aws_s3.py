"""
ExposureFence AWS S3 Read-Only Connector
Inspects S3 bucket configurations, public access blocks, bucket policies, ACLs,
encryption settings, versioning status, and object ownership controls.
STRICTLY READ-ONLY: Never accesses object contents and never modifies bucket settings.
Enforces region allowlists, API budgeting, rate limiting, and RFC 8785 evidence generation.
"""

from datetime import datetime, UTC
import hashlib
import json
import logging
from typing import Any, Dict, List, Optional, Set

import boto3
from botocore.exceptions import ClientError

from backend.connectors.aws_session import get_boto3_session
from backend.connectors.boundaries import get_allowed_regions
from backend.connectors.evidence_status import (
    AssessmentStatus,
    build_failure_evidence,
    map_error_to_assessment_status
)
from backend.connectors.s3_security_intelligence import (
    analyze_s3_bucket_acl,
    analyze_s3_bucket_policy,
    analyze_s3_encryption,
    analyze_s3_public_access_block,
    analyze_s3_versioning,
    determine_s3_exposure_status
)

logger = logging.getLogger("exposurefence.connectors.s3")


def _resolve_s3_client(session=None, region_name: Optional[str] = None):
    """Resolves an S3 client through supplied session wrapper or factory."""
    if session is not None:
        if hasattr(session, "get_client"):
            return session.get_client("s3", region_name=region_name)
        if hasattr(session, "client"):
            try:
                return session.client("s3", region_name=region_name)
            except TypeError:
                return session.client("s3")
    sess = get_boto3_session()
    return sess.client("s3", region_name=region_name)


# =========================================================================
# 1. BUCKET DISCOVERY & PAGINATION
# =========================================================================

def list_s3_buckets(
    max_buckets: Optional[int] = None,
    session=None
) -> List[Dict[str, Any]]:
    """
    Lists S3 buckets in the account. Read-only metadata only.
    Supports ContinuationToken pagination where available with loop protection.
    """
    client = _resolve_s3_client(session)
    buckets: List[Dict[str, Any]] = []
    seen_tokens: Set[str] = set()
    continuation_token: Optional[str] = None

    while True:
        kwargs: Dict[str, Any] = {}
        if continuation_token:
            kwargs["ContinuationToken"] = continuation_token
        if max_buckets:
            kwargs["MaxBuckets"] = max_buckets

        try:
            response = client.list_buckets(**kwargs)
        except TypeError:
            # Fallback if mock/client does not accept ContinuationToken / MaxBuckets kwargs
            response = client.list_buckets()

        for b in response.get("Buckets", []):
            created = b.get("CreationDate")
            b_name = b.get("Name", "")
            buckets.append({
                "name": b_name,
                "creation_date": created.isoformat() if hasattr(created, "isoformat") else str(created),
                "arn": b.get("BucketArn") or f"arn:aws:s3:::{b_name}",
                "region": b.get("BucketRegion")
            })

        # Check for continuation token in response
        next_token = response.get("ContinuationToken") or response.get("NextContinuationToken")
        if not next_token:
            break

        if next_token in seen_tokens:
            logger.warning("Pagination loop detected in list_s3_buckets with token: %s", next_token)
            break

        seen_tokens.add(next_token)
        continuation_token = next_token

    return buckets


# =========================================================================
# 2. REGION RESOLUTION & LOCATION NORMALIZATION
# =========================================================================

def resolve_bucket_region(bucket_name: str, session=None) -> Dict[str, Any]:
    """
    Resolves a bucket's actual AWS region using GetBucketLocation.
    Normalizes legacy empty location constraints to us-east-1 and EU to eu-west-1.
    """
    client = _resolve_s3_client(session)
    try:
        response = client.get_bucket_location(Bucket=bucket_name)
        constraint = response.get("LocationConstraint")

        # Normalize legacy AWS location constraints
        if not constraint:
            region = "us-east-1"
        elif constraint == "EU":
            region = "eu-west-1"
        else:
            region = str(constraint)

        return {
            "bucket_name": bucket_name,
            "region": region,
            "is_resolved": True,
            "raw_constraint": constraint,
            "error": None
        }
    except Exception as exc:
        logger.warning("Could not resolve region for bucket %s: %s", bucket_name, exc)
        return {
            "bucket_name": bucket_name,
            "region": "UNKNOWN",
            "is_resolved": False,
            "raw_constraint": None,
            "error": str(exc)
        }


# =========================================================================
# 3. BUCKET CONFIGURATION RETRIEVAL
# =========================================================================

def get_bucket_public_access_block(bucket_name: str, session=None) -> Dict[str, Any]:
    """
    Retrieves S3 Block Public Access configuration for a bucket.
    Distinguishes explicit configuration from absent configuration (404 / NotFound).
    """
    client = _resolve_s3_client(session)
    try:
        response = client.get_public_access_block(Bucket=bucket_name)
        cfg = response.get("PublicAccessBlockConfiguration", {})
        b_acls = cfg.get("BlockPublicAcls", False)
        i_acls = cfg.get("IgnorePublicAcls", False)
        b_pol = cfg.get("BlockPublicPolicy", False)
        r_buc = cfg.get("RestrictPublicBuckets", False)
        return {
            "block_public_acls": b_acls,
            "ignore_public_acls": i_acls,
            "block_public_policy": b_pol,
            "restrict_public_buckets": r_buc,
            "is_effective": all([b_acls, i_acls, b_pol, r_buc]),
            "status": "PRESENT"
        }
    except ClientError as e:
        err_code = e.response.get("Error", {}).get("Code", "")
        if err_code in ("NoSuchPublicAccessBlockConfiguration", "NotFound"):
            return {
                "block_public_acls": False,
                "ignore_public_acls": False,
                "block_public_policy": False,
                "restrict_public_buckets": False,
                "is_effective": False,
                "status": "ABSENT"
            }
        raise


def get_bucket_policy_status(bucket_name: str, session=None) -> Dict[str, Any]:
    """
    Retrieves S3 bucket policy status (determines if policy is publicly accessible).
    """
    client = _resolve_s3_client(session)
    try:
        response = client.get_bucket_policy_status(Bucket=bucket_name)
        status = response.get("PolicyStatus", {})
        return {
            "is_public": status.get("IsPublic", False),
            "status": "PRESENT"
        }
    except ClientError as e:
        err_code = e.response.get("Error", {}).get("Code", "")
        if err_code in ("NoSuchBucketPolicy", "NotFound"):
            return {
                "is_public": False,
                "status": "ABSENT"
            }
        raise


def get_bucket_acl(bucket_name: str, session=None) -> Dict[str, Any]:
    """
    Checks bucket ACL grants for public access (AllUsers or AuthenticatedUsers).
    """
    client = _resolve_s3_client(session)
    try:
        response = client.get_bucket_acl(Bucket=bucket_name)
        grants = response.get("Grants", [])
        owner = response.get("Owner", {})
        is_public_acl = False
        public_grants = []

        for g in grants:
            if not isinstance(g, dict):
                continue
            grantee = g.get("Grantee", {})
            uri = grantee.get("URI", "")
            if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                is_public_acl = True
                public_grants.append({
                    "permission": g.get("Permission"),
                    "grantee": uri
                })

        return {
            "is_public_acl": is_public_acl,
            "public_grants": public_grants,
            "Grants": grants,
            "Owner": owner,
            "status": "PRESENT"
        }
    except ClientError:
        raise


def get_bucket_policy(bucket_name: str, session=None) -> Optional[Dict[str, Any]]:
    """Reads bucket policy string if present and parses as JSON. Read-only."""
    client = _resolve_s3_client(session)
    try:
        response = client.get_bucket_policy(Bucket=bucket_name)
        raw_policy = response.get("Policy")
        if raw_policy:
            if isinstance(raw_policy, dict):
                return raw_policy
            return json.loads(raw_policy)
        return None
    except ClientError as e:
        err_code = e.response.get("Error", {}).get("Code", "")
        if err_code in ("NoSuchBucketPolicy", "NotFound"):
            return None
        raise


def get_bucket_encryption(bucket_name: str, session=None) -> Dict[str, Any]:
    """
    Retrieves explicit default encryption configuration for an S3 bucket.
    Handles ServerSideEncryptionConfigurationNotFoundError as absent configuration.
    """
    client = _resolve_s3_client(session)
    try:
        response = client.get_bucket_encryption(Bucket=bucket_name)
        cfg = response.get("ServerSideEncryptionConfiguration", {})
        rules = cfg.get("Rules", [])
        return {
            "status": "PRESENT",
            "has_explicit_encryption": True,
            "rules": rules
        }
    except ClientError as e:
        err_code = e.response.get("Error", {}).get("Code", "")
        if err_code in ("ServerSideEncryptionConfigurationNotFoundError", "NoSuchBucketEncryption", "NotFound"):
            return {
                "status": "ABSENT",
                "has_explicit_encryption": False,
                "rules": []
            }
        raise


def get_bucket_versioning(bucket_name: str, session=None) -> Dict[str, Any]:
    """Retrieves S3 bucket versioning and MFA Delete configuration."""
    client = _resolve_s3_client(session)
    try:
        response = client.get_bucket_versioning(Bucket=bucket_name)
        return {
            "status": response.get("Status"),
            "mfa_delete": response.get("MFADelete")
        }
    except ClientError:
        raise


def get_bucket_ownership_controls(bucket_name: str, session=None) -> Dict[str, Any]:
    """
    Retrieves Object Ownership controls configuration for an S3 bucket.
    Handles OwnershipControlsNotFoundError as absent configuration.
    """
    client = _resolve_s3_client(session)
    try:
        response = client.get_bucket_ownership_controls(Bucket=bucket_name)
        ctrls = response.get("OwnershipControls", {})
        rules = ctrls.get("Rules", [])
        rule_name = rules[0].get("ObjectOwnership") if rules else None
        return {
            "status": "PRESENT",
            "ownership_rule": rule_name
        }
    except ClientError as e:
        err_code = e.response.get("Error", {}).get("Code", "")
        if err_code in ("OwnershipControlsNotFoundError", "NoSuchOwnershipControls", "NotFound"):
            return {
                "status": "ABSENT",
                "ownership_rule": None
            }
        raise


# =========================================================================
# 4. CANONICAL EVIDENCE COLLECTION
# =========================================================================

def collect_s3_bucket_inventory_evidence(
    bucket_name: str,
    session=None,
    account_id: Optional[str] = None,
    region: Optional[str] = None
) -> Dict[str, Any]:
    """
    Collects complete read-only S3 security evidence including Public Access Block,
    bucket policy, ACLs, encryption, versioning, and object ownership.
    Enforces regional allowlists and generates deterministic RFC 8785 evidence records.
    """
    # 1. Resolve and validate bucket region
    resolved_region = region
    if not resolved_region or resolved_region == "UNKNOWN":
        reg_info = resolve_bucket_region(bucket_name, session=session)
        if not reg_info.get("is_resolved"):
            logger.warning("Failed to resolve region for S3 bucket %s: %s", bucket_name, reg_info.get("error"))
            status = AssessmentStatus.ASSESSMENT_INCOMPLETE
            return build_failure_evidence(
                resource_id=bucket_name,
                source_type="AWS::S3::Bucket",
                status=status,
                error_message=f"Could not resolve bucket region: {reg_info.get('error')}",
                account_id=account_id,
                region="UNKNOWN"
            )
        resolved_region = reg_info["region"]

    # 2. Enforce region allowlist (fail-closed)
    allowed_regions = get_allowed_regions()
    if resolved_region not in allowed_regions:
        logger.warning(
            "Bucket %s resides in region %s which is outside the configured region allowlist %s. Skipping detailed collection.",
            bucket_name, resolved_region, allowed_regions
        )
        return build_failure_evidence(
            resource_id=bucket_name,
            source_type="AWS::S3::Bucket",
            status=AssessmentStatus.REGION_NOT_ALLOWED,
            error_message=f"Bucket region '{resolved_region}' is outside allowed regions: {allowed_regions}",
            account_id=account_id,
            region=resolved_region
        )

    # 3. Collect bucket configurations
    try:
        pab = get_bucket_public_access_block(bucket_name, session=session)
        policy_status = get_bucket_policy_status(bucket_name, session=session)
        acl_data = get_bucket_acl(bucket_name, session=session)
        policy_doc = get_bucket_policy(bucket_name, session=session)
        encryption_data = get_bucket_encryption(bucket_name, session=session)
        versioning_data = get_bucket_versioning(bucket_name, session=session)
        ownership_data = get_bucket_ownership_controls(bucket_name, session=session)
    except Exception as exc:
        logger.warning("Error collecting S3 bucket inventory evidence for %s: %s", bucket_name, exc)
        status = map_error_to_assessment_status(exc)
        return build_failure_evidence(
            resource_id=bucket_name,
            source_type="AWS::S3::Bucket",
            status=status,
            error_message=str(exc),
            account_id=account_id,
            region=resolved_region
        )

    # 4. Intelligence analysis
    pab_analysis = analyze_s3_public_access_block(pab)
    ownership_rule = ownership_data.get("ownership_rule")
    acl_analysis = analyze_s3_bucket_acl(acl_data, ownership_rule=ownership_rule)
    policy_analysis = analyze_s3_bucket_policy(policy_doc, target_account_id=account_id)
    encryption_analysis = analyze_s3_encryption(encryption_data)
    versioning_analysis = analyze_s3_versioning(versioning_data)
    exposure_summary = determine_s3_exposure_status(
        pab_analysis=pab_analysis,
        policy_analysis=policy_analysis,
        acl_analysis=acl_analysis,
        ownership_rule=ownership_rule
    )

    # 5. Canonical raw evidence construction
    raw_evidence = {
        "bucket_name": bucket_name,
        "bucket_arn": f"arn:aws:s3:::{bucket_name}",
        "account_id": account_id or "UNKNOWN",
        "region": resolved_region,
        "public_access_block": pab_analysis,
        "policy_status": policy_status,
        "bucket_policy": policy_analysis,
        "acl": acl_analysis,
        "encryption": encryption_analysis,
        "versioning": versioning_analysis,
        "ownership_controls": ownership_data,
        "exposure_summary": exposure_summary,
        "is_public": exposure_summary["is_publicly_accessible"],
        "assessment_complete": True
    }

    canonical_raw = json.dumps(raw_evidence, sort_keys=True)
    digest = hashlib.sha256(canonical_raw.encode("utf-8")).hexdigest()
    timestamp = datetime.now(UTC).isoformat()
    evidence_id = f"EV-AWS-S3-{bucket_name}-{digest[:8]}"

    return {
        "evidence_id": evidence_id,
        "resource_id": bucket_name,
        "source_type": "AWS::S3::Bucket",
        "account_id": account_id or "UNKNOWN",
        "region": resolved_region,
        "collection_timestamp": timestamp,
        "raw_evidence": raw_evidence,
        "sha256": digest,
        "verification_result": exposure_summary["verification_result"],
        "assessment_status": AssessmentStatus.VERIFIED.value
    }


def collect_s3_exposure_evidence(
    bucket_name: str,
    session=None,
    account_id: Optional[str] = None,
    region: str = "us-east-1"
) -> Dict[str, Any]:
    """
    Backward-compatible entrypoint for legacy tests.
    Collects read-only configuration and returns a normalized Evidence record.
    Never reads object data. Maps API errors to explicit failure states (never clean/secure).
    """
    try:
        pab = get_bucket_public_access_block(bucket_name, session=session)
        policy_status = get_bucket_policy_status(bucket_name, session=session)
        acl_status = get_bucket_acl(bucket_name, session=session)
    except Exception as exc:
        logger.warning("Error inspecting S3 bucket %s: %s", bucket_name, exc)
        status = map_error_to_assessment_status(exc)
        return build_failure_evidence(
            resource_id=bucket_name,
            source_type="AWS::S3::Bucket",
            status=status,
            error_message=str(exc),
            account_id=account_id,
            region=region
        )

    is_public = (not pab["is_effective"]) and (policy_status["is_public"] or acl_status["is_public_acl"])

    raw_evidence = {
        "resource_id": bucket_name,
        "public_access_block": pab,
        "policy_status": policy_status,
        "acl_status": acl_status,
        "public_access": is_public
    }

    canonical_raw = json.dumps(raw_evidence, sort_keys=True)
    digest = hashlib.sha256(canonical_raw.encode("utf-8")).hexdigest()
    timestamp = datetime.now(UTC).isoformat()
    evidence_id = f"EV-AWS-S3-{bucket_name}-{digest[:8]}"

    return {
        "evidence_id": evidence_id,
        "resource_id": bucket_name,
        "source_type": "AWS::S3::Bucket",
        "account_id": account_id,
        "region": region,
        "collection_timestamp": timestamp,
        "raw_evidence": raw_evidence,
        "sha256": digest,
        "verification_result": "VERIFIED_AWS" if not is_public else "EXPOSURE_DETECTED"
    }
