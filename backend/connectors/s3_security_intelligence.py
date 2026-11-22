"""
ExposureFence — S3 Bucket Security Intelligence Engine
Provides deterministic evaluation of S3 Public Access Block, bucket policies,
ACL grants, Object Ownership controls, default encryption, and versioning.
Strictly evidence-backed: distinguishes confirmed effective public exposure from
conditional access, and explicit bucket configuration from AWS default service behavior.
"""

from datetime import datetime, timezone
import hashlib
import json
import logging
import re
from typing import Any, Dict, List, Optional, Set

try:
    import rfc8785
    HAS_RFC8785 = True
except ImportError:
    HAS_RFC8785 = False

logger = logging.getLogger("exposurefence.connectors.s3.intelligence")

ALL_USERS_URI = "http://acs.amazonaws.com/groups/global/AllUsers"
AUTHENTICATED_USERS_URI = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"

RESTRICTIVE_CONDITION_KEYS = {
    "aws:principalarn",
    "aws:principalaccount",
    "aws:principalorgid",
    "aws:sourcearn",
    "aws:sourceaccount",
    "aws:sourceowner",
    "aws:sourcevpce",
    "aws:sourcevpc",
    "aws:sourceip",
}


def normalize_s3_policy_document(raw_doc: Any) -> Dict[str, Any]:
    """
    Normalizes an S3 bucket policy document into canonical structure.
    Ensures Statement, Action, Resource, and Principal are uniformly lists or dicts.
    """
    if isinstance(raw_doc, str):
        try:
            doc = json.loads(raw_doc)
        except Exception:
            return {}
    elif isinstance(raw_doc, dict):
        doc = json.loads(json.dumps(raw_doc))
    else:
        return {}

    statements = doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    normalized_statements = []
    for stmt in statements:
        if not isinstance(stmt, dict):
            continue
        n_stmt = dict(stmt)

        # Actions
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        n_stmt["Action"] = sorted(actions)

        # Resources
        resources = stmt.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]
        n_stmt["Resource"] = sorted(resources)

        # Principal
        principal = stmt.get("Principal")
        if isinstance(principal, str):
            n_stmt["Principal"] = principal
        elif isinstance(principal, dict):
            n_principal = {}
            for p_key, p_val in sorted(principal.items()):
                if isinstance(p_val, str):
                    n_principal[p_key] = [p_val]
                elif isinstance(p_val, list):
                    n_principal[p_key] = sorted(p_val)
                else:
                    n_principal[p_key] = p_val
            n_stmt["Principal"] = n_principal

        normalized_statements.append(n_stmt)

    doc["Statement"] = normalized_statements
    return doc


def compute_s3_policy_hash(policy_doc: Optional[Dict[str, Any]]) -> str:
    """Computes deterministic SHA-256 hash using RFC 8785 canonical JSON if available."""
    if not policy_doc:
        return hashlib.sha256(b"{}").hexdigest()

    norm = normalize_s3_policy_document(policy_doc)
    if HAS_RFC8785:
        canonical_bytes = rfc8785.dumps(norm)
    else:
        canonical_bytes = json.dumps(norm, sort_keys=True, separators=(",", ":")).encode("utf-8")

    return hashlib.sha256(canonical_bytes).hexdigest()


# =========================================================================
# 1. PUBLIC ACCESS BLOCK ANALYSIS
# =========================================================================

def analyze_s3_public_access_block(pab_config: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Evaluates S3 Block Public Access configuration.
    Differentiates between complete protection, partial configuration, and absent configuration.
    """
    if not pab_config:
        return {
            "has_configuration": False,
            "block_public_acls": False,
            "ignore_public_acls": False,
            "block_public_policy": False,
            "restrict_public_buckets": False,
            "is_effective": False,
            "exposure_risk": "HIGH",
            "notes": "No explicit Public Access Block configuration present on bucket."
        }

    b_acls = bool(pab_config.get("block_public_acls") or pab_config.get("BlockPublicAcls", False))
    i_acls = bool(pab_config.get("ignore_public_acls") or pab_config.get("IgnorePublicAcls", False))
    b_policy = bool(pab_config.get("block_public_policy") or pab_config.get("BlockPublicPolicy", False))
    r_buckets = bool(pab_config.get("restrict_public_buckets") or pab_config.get("RestrictPublicBuckets", False))

    is_effective = b_acls and i_acls and b_policy and r_buckets

    if is_effective:
        risk = "NONE"
    elif not any([b_acls, i_acls, b_policy, r_buckets]):
        risk = "HIGH"
    else:
        risk = "MODERATE"

    return {
        "has_configuration": True,
        "block_public_acls": b_acls,
        "ignore_public_acls": i_acls,
        "block_public_policy": b_policy,
        "restrict_public_buckets": r_buckets,
        "is_effective": is_effective,
        "exposure_risk": risk,
        "notes": "All 4 Public Access Block settings enabled." if is_effective else "Partial Public Access Block settings enabled."
    }


# =========================================================================
# 2. BUCKET POLICY ANALYSIS
# =========================================================================

def analyze_s3_bucket_policy(
    policy_doc: Optional[Dict[str, Any]],
    target_account_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Analyzes bucket policy for public exposure, cross-account access, and conditional restrictions.
    INVARIANT: A wildcard principal statement is NOT unconditionally public if restricted by conditions.
    """
    if not policy_doc:
        return {
            "has_policy": False,
            "is_unconditionally_public": False,
            "is_conditionally_restricted": False,
            "cross_account_principals": [],
            "wildcard_actions": [],
            "policy_hash": compute_s3_policy_hash(None),
            "findings": []
        }

    norm = normalize_s3_policy_document(policy_doc)
    policy_hash = compute_s3_policy_hash(norm)

    is_unconditionally_public = False
    is_conditionally_restricted = False
    cross_account_principals: Set[str] = set()
    wildcard_actions: Set[str] = set()
    findings: List[Dict[str, Any]] = []

    for idx, stmt in enumerate(norm.get("Statement", [])):
        effect = stmt.get("Effect", "Allow")
        if effect != "Allow":
            continue

        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        for act in actions:
            if act in ("*", "s3:*") or act.endswith(":*"):
                wildcard_actions.add(act)

        # Inspect Principal
        principal = stmt.get("Principal")
        has_wildcard_principal = False

        if principal == "*":
            has_wildcard_principal = True
        elif isinstance(principal, dict):
            aws_p = principal.get("AWS")
            if aws_p == "*" or (isinstance(aws_p, list) and "*" in aws_p):
                has_wildcard_principal = True
            elif isinstance(aws_p, str):
                p_list = [aws_p]
            elif isinstance(aws_p, list):
                p_list = aws_p
            else:
                p_list = []

            for p_str in p_list:
                if not isinstance(p_str, str):
                    continue
                # Extract cross-account AWS principals (e.g. arn:aws:iam::999988887777:root)
                m = re.search(r"arn:aws:iam::(\d{12}):", p_str)
                if m:
                    acct = m.group(1)
                    if target_account_id and acct != target_account_id:
                        cross_account_principals.add(p_str)
                elif re.match(r"^\d{12}$", p_str):
                    if target_account_id and p_str != target_account_id:
                        cross_account_principals.add(p_str)

        # Inspect Conditions
        conditions = stmt.get("Condition", {})
        has_restrictive_condition = False
        condition_keys_found: List[str] = []

        if isinstance(conditions, dict):
            for op, cond_map in conditions.items():
                if isinstance(cond_map, dict):
                    for k in cond_map.keys():
                        k_lower = k.lower()
                        condition_keys_found.append(k)
                        if k_lower in RESTRICTIVE_CONDITION_KEYS:
                            has_restrictive_condition = True

        if has_wildcard_principal:
            if has_restrictive_condition:
                is_conditionally_restricted = True
                findings.append({
                    "rule_id": "S3-CONDITIONAL-WILDCARD",
                    "severity": "LOW",
                    "statement_index": idx,
                    "description": f"Statement contains wildcard principal restricted by condition keys: {condition_keys_found}"
                })
            else:
                is_unconditionally_public = True
                findings.append({
                    "rule_id": "S3-PUBLIC-POLICY-ALLOW",
                    "severity": "CRITICAL",
                    "statement_index": idx,
                    "description": "Statement grants unrestricted public access (Principal: '*' without restrictive condition)."
                })

    return {
        "has_policy": True,
        "is_unconditionally_public": is_unconditionally_public,
        "is_conditionally_restricted": is_conditionally_restricted,
        "cross_account_principals": sorted(list(cross_account_principals)),
        "wildcard_actions": sorted(list(wildcard_actions)),
        "policy_hash": policy_hash,
        "findings": findings
    }


# =========================================================================
# 3. BUCKET ACL ANALYSIS
# =========================================================================

def analyze_s3_bucket_acl(
    acl_data: Optional[Dict[str, Any]],
    ownership_rule: Optional[str] = None
) -> Dict[str, Any]:
    """
    Evaluates S3 Bucket ACL grants for public exposure.
    If Object Ownership is BucketOwnerEnforced, ACLs are completely disabled by S3.
    """
    if ownership_rule == "BucketOwnerEnforced":
        return {
            "is_public_acl": False,
            "is_public_read": False,
            "is_public_write": False,
            "all_users_grants": [],
            "authenticated_users_grants": [],
            "acls_disabled": True,
            "notes": "ACLs are disabled on this bucket because Object Ownership is BucketOwnerEnforced."
        }

    if not acl_data:
        return {
            "is_public_acl": False,
            "is_public_read": False,
            "is_public_write": False,
            "all_users_grants": [],
            "authenticated_users_grants": [],
            "acls_disabled": False,
            "notes": "No ACL grant data provided."
        }

    grants = acl_data.get("Grants", [])
    all_users_grants = []
    auth_users_grants = []
    is_public_read = False
    is_public_write = False

    for g in grants:
        if not isinstance(g, dict):
            continue
        grantee = g.get("Grantee", {})
        uri = grantee.get("URI", "")
        perm = g.get("Permission", "")

        if uri == ALL_USERS_URI:
            all_users_grants.append(perm)
            if perm in ("READ", "FULL_CONTROL"):
                is_public_read = True
            if perm in ("WRITE", "FULL_CONTROL"):
                is_public_write = True
        elif uri == AUTHENTICATED_USERS_URI:
            auth_users_grants.append(perm)
            if perm in ("READ", "FULL_CONTROL"):
                is_public_read = True
            if perm in ("WRITE", "FULL_CONTROL"):
                is_public_write = True

    is_public = len(all_users_grants) > 0 or len(auth_users_grants) > 0

    return {
        "is_public_acl": is_public,
        "is_public_read": is_public_read,
        "is_public_write": is_public_write,
        "all_users_grants": sorted(all_users_grants),
        "authenticated_users_grants": sorted(auth_users_grants),
        "acls_disabled": False,
        "notes": "Public ACL grants detected." if is_public else "No public ACL grants detected."
    }


# =========================================================================
# 4. ENCRYPTION INTELLIGENCE
# =========================================================================

def analyze_s3_encryption(encryption_data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Analyzes S3 bucket server-side encryption configuration.
    CRITICAL: Absence of explicit bucket-level encryption does NOT mean objects are plaintext;
    AWS S3 applies default SSE-S3 encryption at rest for all buckets since January 2023.
    """
    if not encryption_data or not encryption_data.get("rules"):
        return {
            "has_explicit_configuration": False,
            "encryption_type": "SSE-S3 (AWS Default at Rest)",
            "sse_algorithm": "AES256",
            "kms_master_key_id": None,
            "bucket_key_enabled": False,
            "plaintext_objects_claimed": False,
            "is_kms": False,
            "status": "DEFAULT_ENCRYPTION_ACTIVE",
            "notes": "No explicit bucket encryption rule found. AWS S3 enforces default SSE-S3 at rest for all objects."
        }

    rules = encryption_data.get("rules", [])
    first_rule = rules[0] if rules else {}
    def_enc = first_rule.get("apply_server_side_encryption_by_default") or first_rule.get("ApplyServerSideEncryptionByDefault", {})
    algo = def_enc.get("SSEAlgorithm") or def_enc.get("sse_algorithm") or "AES256"
    kms_key = def_enc.get("KMSMasterKeyID") or def_enc.get("kms_master_key_id")
    bucket_key = bool(first_rule.get("BucketKeyEnabled") or first_rule.get("bucket_key_enabled", False))

    is_kms = "kms" in str(algo).lower()
    enc_type = "SSE-KMS" if algo == "aws:kms" else ("DSSE-KMS" if algo == "aws:kms:dsse" else "SSE-S3 (Explicit)")

    return {
        "has_explicit_configuration": True,
        "encryption_type": enc_type,
        "sse_algorithm": algo,
        "kms_master_key_id": kms_key,
        "bucket_key_enabled": bucket_key,
        "plaintext_objects_claimed": False,
        "is_kms": is_kms,
        "status": "EXPLICIT_ENCRYPTION_ACTIVE",
        "notes": f"Bucket explicitly configured with {enc_type} encryption."
    }


# =========================================================================
# 5. VERSIONING INTELLIGENCE
# =========================================================================

def analyze_s3_versioning(versioning_data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Analyzes S3 bucket versioning and MFA Delete state.
    """
    if not versioning_data:
        return {
            "status": "Absent",
            "is_enabled": False,
            "is_suspended": False,
            "mfa_delete": "Absent",
            "recovery_readiness": "LOW",
            "notes": "Versioning is not enabled on this bucket."
        }

    raw_status = versioning_data.get("status") or versioning_data.get("Status")
    mfa_delete = versioning_data.get("mfa_delete") or versioning_data.get("MFADelete") or "Absent"

    is_enabled = raw_status == "Enabled"
    is_suspended = raw_status == "Suspended"

    if is_enabled and mfa_delete == "Enabled":
        readiness = "HIGH"
    elif is_enabled:
        readiness = "MODERATE"
    else:
        readiness = "LOW"

    return {
        "status": raw_status or "Absent",
        "is_enabled": is_enabled,
        "is_suspended": is_suspended,
        "mfa_delete": mfa_delete,
        "recovery_readiness": readiness,
        "notes": f"Versioning is {raw_status or 'Absent'} (MFA Delete: {mfa_delete})."
    }


# =========================================================================
# 6. COMPREHENSIVE EXPOSURE SYNTHESIS
# =========================================================================

def determine_s3_exposure_status(
    pab_analysis: Dict[str, Any],
    policy_analysis: Dict[str, Any],
    acl_analysis: Dict[str, Any],
    ownership_rule: Optional[str] = None
) -> Dict[str, Any]:
    """
    Synthesizes Public Access Block, bucket policy, ACL, and Object Ownership
    to determine confirmed effective public accessibility.
    """
    # 1. Check if Block Public Access overrides public exposure
    block_public_policy = pab_analysis.get("block_public_policy", False)
    ignore_public_acls = pab_analysis.get("ignore_public_acls", False)
    is_pab_effective = pab_analysis.get("is_effective", False)

    policy_public = policy_analysis.get("is_unconditionally_public", False)
    effective_policy_public = policy_public and not block_public_policy

    acl_public = acl_analysis.get("is_public_acl", False)
    effective_acl_public = acl_public and not ignore_public_acls and (ownership_rule != "BucketOwnerEnforced")

    is_publicly_accessible = effective_policy_public or effective_acl_public

    exposure_reasons: List[str] = []
    if effective_policy_public:
        exposure_reasons.append("Unrestricted public bucket policy (not blocked by Public Access Block)")
    if effective_acl_public:
        exposure_reasons.append("Public ACL grants active (not ignored by Public Access Block or BucketOwnerEnforced)")

    if is_publicly_accessible:
        verdict = "EXPOSURE_DETECTED"
        exposure_level = "CONFIRMED_PUBLIC"
        confidence = 1.0
    elif policy_analysis.get("is_conditionally_restricted", False):
        verdict = "CONDITIONALLY_RESTRICTED"
        exposure_level = "RESTRICTED_ACCESS"
        confidence = 0.90
    elif is_pab_effective:
        verdict = "VERIFIED_SECURE"
        exposure_level = "PROTECTED_BY_PAB"
        confidence = 1.0
    else:
        verdict = "VERIFIED_SECURE"
        exposure_level = "PRIVATE"
        confidence = 1.0

    return {
        "is_publicly_accessible": is_publicly_accessible,
        "effective_policy_public": effective_policy_public,
        "effective_acl_public": effective_acl_public,
        "exposure_level": exposure_level,
        "exposure_reasons": exposure_reasons,
        "verification_result": verdict,
        "confidence": confidence
    }
