"""
ExposureFence AWS S3 Read-Only Connector
Inspects S3 bucket configurations, public access blocks, bucket policies, and ACLs.
STRICTLY READ-ONLY: Never accesses object contents and never modifies bucket settings.
"""

from datetime import datetime, UTC
import hashlib
import json
import logging
from typing import Any, Dict, List, Optional

from botocore.exceptions import ClientError
from backend.connectors.aws_session import get_boto3_session

logger = logging.getLogger("exposurefence.connectors.s3")


def list_s3_buckets(session=None) -> List[Dict[str, Any]]:
    """Lists S3 buckets in the account. Read-only metadata only."""
    sess = session or get_boto3_session()
    client = sess.client("s3")
    response = client.list_buckets()
    buckets = []
    for b in response.get("Buckets", []):
        created = b.get("CreationDate")
        buckets.append({
            "name": b.get("Name"),
            "creation_date": created.isoformat() if hasattr(created, "isoformat") else str(created)
        })
    return buckets


def get_bucket_public_access_block(bucket_name: str, session=None) -> Dict[str, Any]:
    """Retrieves S3 Block Public Access configuration for a bucket."""
    sess = session or get_boto3_session()
    client = sess.client("s3")
    try:
        response = client.get_public_access_block(Bucket=bucket_name)
        cfg = response.get("PublicAccessBlockConfiguration", {})
        return {
            "block_public_acls": cfg.get("BlockPublicAcls", False),
            "ignore_public_acls": cfg.get("IgnorePublicAcls", False),
            "block_public_policy": cfg.get("BlockPublicPolicy", False),
            "restrict_public_buckets": cfg.get("RestrictPublicBuckets", False),
            "is_effective": all([
                cfg.get("BlockPublicAcls", False),
                cfg.get("IgnorePublicAcls", False),
                cfg.get("BlockPublicPolicy", False),
                cfg.get("RestrictPublicBuckets", False)
            ])
        }
    except ClientError as e:
        err_code = e.response.get("Error", {}).get("Code", "")
        if err_code in ("NoSuchPublicAccessBlockConfiguration", "NotFound"):
            return {
                "block_public_acls": False,
                "ignore_public_acls": False,
                "block_public_policy": False,
                "restrict_public_buckets": False,
                "is_effective": False
            }
        raise


def get_bucket_policy_status(bucket_name: str, session=None) -> Dict[str, Any]:
    """Retrieves S3 bucket policy status (determines if policy is publicly accessible)."""
    sess = session or get_boto3_session()
    client = sess.client("s3")
    try:
        response = client.get_bucket_policy_status(Bucket=bucket_name)
        status = response.get("PolicyStatus", {})
        return {
            "is_public": status.get("IsPublic", False)
        }
    except ClientError as e:
        err_code = e.response.get("Error", {}).get("Code", "")
        if err_code in ("NoSuchBucketPolicy", "NotFound"):
            return {"is_public": False}
        raise


def get_bucket_acl(bucket_name: str, session=None) -> Dict[str, Any]:
    """Checks bucket ACL grants for public access (AllUsers or AuthenticatedUsers)."""
    sess = session or get_boto3_session()
    client = sess.client("s3")
    try:
        response = client.get_bucket_acl(Bucket=bucket_name)
        grants = response.get("Grants", [])
        is_public_acl = False
        public_grants = []

        for g in grants:
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
            "public_grants": public_grants
        }
    except ClientError:
        raise


def get_bucket_policy(bucket_name: str, session=None) -> Optional[Dict[str, Any]]:
    """Reads bucket policy string if present and parses as JSON. Read-only."""
    sess = session or get_boto3_session()
    client = sess.client("s3")
    try:
        response = client.get_bucket_policy(Bucket=bucket_name)
        raw_policy = response.get("Policy")
        if raw_policy:
            return json.loads(raw_policy)
        return None
    except ClientError as e:
        err_code = e.response.get("Error", {}).get("Code", "")
        if err_code in ("NoSuchBucketPolicy", "NotFound"):
            return None
        raise


def collect_s3_exposure_evidence(bucket_name: str, session=None, account_id: Optional[str] = None, region: str = "us-east-1") -> Dict[str, Any]:
    """
    Collects read-only configuration and returns a normalized Evidence record.
    Never reads object data.
    """
    pab = get_bucket_public_access_block(bucket_name, session=session)
    policy_status = get_bucket_policy_status(bucket_name, session=session)
    acl_status = get_bucket_acl(bucket_name, session=session)

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
