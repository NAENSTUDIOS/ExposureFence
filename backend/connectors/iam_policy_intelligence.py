"""
ExposureFence — IAM Policy Intelligence & Risk Analysis Engine
Normalizes IAM policy documents, evaluates administrative wildcards, detects Bishop Fox /
Rhino Security Labs privilege escalation vectors, inspects trust policies, and identifies
cross-account trust exposures with rigorous evidence grounding.
"""

import hashlib
import json
import re
from typing import Any, Dict, List, Optional, Set, Tuple

ACCOUNT_IN_ARN_REGEX = re.compile(r"arn:aws[a-z0-9-]*:[a-z0-9-]+:[a-z0-9-]*:(\d{12}):")

# Known Privilege Escalation Vectors
PRIVILEGE_ESCALATION_DEFINITIONS = [
    {
        "vector_id": "ESC-01",
        "name": "Wildcard Administrator Access",
        "required_action_groups": [["*"]],
        "severity": "CRITICAL",
        "description": "Identity possesses unrestricted '*' action on all resources, conferring full administrative privilege."
    },
    {
        "vector_id": "ESC-02",
        "name": "PassRole + EC2 RunInstances Escalation",
        "required_action_groups": [["iam:passrole"], ["ec2:runinstances"]],
        "severity": "HIGH",
        "description": "Identity can pass high-privilege roles to newly launched EC2 compute instances."
    },
    {
        "vector_id": "ESC-03",
        "name": "PassRole + Lambda CreateFunction Escalation",
        "required_action_groups": [["iam:passrole"], ["lambda:createfunction", "lambda:invokefunction"]],
        "severity": "HIGH",
        "description": "Identity can author and invoke Lambda functions executing under higher-privileged roles."
    },
    {
        "vector_id": "ESC-04",
        "name": "Policy Version Self-Escalation",
        "required_action_groups": [["iam:createpolicyversion", "iam:setdefaultpolicyversion"]],
        "severity": "HIGH",
        "description": "Identity can create or activate new policy versions granting expanded permissions."
    },
    {
        "vector_id": "ESC-05",
        "name": "Policy Attachment Self-Escalation",
        "required_action_groups": [["iam:attachrolepolicy", "iam:attachuserpolicy", "iam:putrolepolicy", "iam:putuserpolicy"]],
        "severity": "HIGH",
        "description": "Identity can attach or inject managed or inline policies to elevate privileges."
    },
    {
        "vector_id": "ESC-06",
        "name": "Group Membership Escalation",
        "required_action_groups": [["iam:addusertogroup"]],
        "severity": "HIGH",
        "description": "Identity can add itself or other users to administrative IAM groups."
    },
    {
        "vector_id": "ESC-07",
        "name": "AssumeRole Privilege Expansion",
        "required_action_groups": [["sts:assumerole"]],
        "severity": "MEDIUM",
        "description": "Identity can assume roles across accounts or trust domains to acquire additional permissions."
    }
]


def normalize_policy_document(doc: Any) -> Dict[str, Any]:
    """
    Normalizes a policy document into a standardized dictionary representation.
    Accepts string JSON, dict, or None.
    """
    if not doc:
        return {}

    if isinstance(doc, str):
        try:
            doc = json.loads(doc)
        except Exception:
            return {}

    if not isinstance(doc, dict):
        return {}

    normalized = {
        "Version": doc.get("Version", "2012-10-17"),
        "Statement": []
    }

    statements = doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    elif not isinstance(statements, list):
        statements = []

    for stmt in statements:
        if not isinstance(stmt, dict):
            continue

        effect = stmt.get("Effect", "Allow")
        sid = stmt.get("Sid")

        # Normalize actions
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        elif not isinstance(actions, list):
            actions = []

        # Normalize resources
        resources = stmt.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]
        elif not isinstance(resources, list):
            resources = []

        norm_stmt: Dict[str, Any] = {
            "Effect": effect,
            "Action": sorted(actions),
            "Resource": sorted(resources)
        }
        if sid:
            norm_stmt["Sid"] = sid
        if "Condition" in stmt and isinstance(stmt["Condition"], dict):
            norm_stmt["Condition"] = stmt["Condition"]
        if "Principal" in stmt:
            norm_stmt["Principal"] = stmt["Principal"]

        normalized["Statement"].append(norm_stmt)

    return normalized


def compute_policy_hash(doc: Dict[str, Any]) -> str:
    """Computes a deterministic SHA-256 hash of a normalized policy document."""
    canonical = json.dumps(doc, sort_keys=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def extract_allowed_actions(doc: Dict[str, Any]) -> Set[str]:
    """Extracts all lowercase allowed actions from a normalized policy document."""
    allowed: Set[str] = set()
    for stmt in doc.get("Statement", []):
        if stmt.get("Effect") == "Allow":
            for act in stmt.get("Action", []):
                allowed.add(str(act).lower())
    return allowed


def is_wildcard_administrator(doc: Dict[str, Any]) -> bool:
    """Checks whether any statement in the document allows '*' action on '*' resource."""
    for stmt in doc.get("Statement", []):
        if stmt.get("Effect") == "Allow":
            actions = [str(a).strip() for a in stmt.get("Action", [])]
            resources = [str(r).strip() for r in stmt.get("Resource", [])]
            if "*" in actions and "*" in resources:
                return True
    return False


def analyze_trust_policy(
    trust_doc: Any,
    target_account_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Evaluates an IAM Role AssumeRolePolicyDocument for wildcard principals, cross-account
    trusts, and external ID requirements.
    """
    norm_doc = normalize_policy_document(trust_doc)
    has_wildcard_principal = False
    trusted_principals: List[str] = []
    cross_account_principals: List[str] = []
    has_external_id_condition = False

    for stmt in norm_doc.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue

        # Check conditions for sts:ExternalId
        conditions = stmt.get("Condition", {})
        for cond_op, cond_keys in conditions.items():
            if isinstance(cond_keys, dict):
                for k in cond_keys.keys():
                    if "externalid" in k.lower():
                        has_external_id_condition = True

        principal = stmt.get("Principal", {})
        if principal == "*":
            has_wildcard_principal = True
            trusted_principals.append("*")
        elif isinstance(principal, dict):
            for p_type, p_val in principal.items():
                p_list = [p_val] if isinstance(p_val, str) else (p_val if isinstance(p_val, list) else [])
                for p_str in p_list:
                    p_str_clean = str(p_str)
                    trusted_principals.append(p_str_clean)
                    if p_str_clean == "*":
                        has_wildcard_principal = True
                    else:
                        m = ACCOUNT_IN_ARN_REGEX.search(p_str_clean)
                        if m:
                            p_account = m.group(1)
                            if target_account_id and p_account != target_account_id:
                                cross_account_principals.append(p_str_clean)

    is_risky = has_wildcard_principal or (len(cross_account_principals) > 0 and not has_external_id_condition)

    return {
        "has_wildcard_principal": has_wildcard_principal,
        "trusted_principals": sorted(list(set(trusted_principals))),
        "cross_account_principals": sorted(list(set(cross_account_principals))),
        "has_external_id_condition": has_external_id_condition,
        "is_risky_trust": is_risky,
        "trust_document": norm_doc
    }


def analyze_privilege_escalation(allowed_actions: Set[str]) -> List[Dict[str, Any]]:
    """
    Evaluates an aggregated set of actions against the known privilege escalation matrix.
    """
    detected = []
    is_admin = "*" in allowed_actions

    for defn in PRIVILEGE_ESCALATION_DEFINITIONS:
        if is_admin:
            detected.append({
                "vector_id": defn["vector_id"],
                "name": defn["name"],
                "severity": defn["severity"],
                "description": defn["description"]
            })
            continue

        matched_all_groups = True
        for group in defn["required_action_groups"]:
            if not any(act.lower() in allowed_actions for act in group):
                matched_all_groups = False
                break

        if matched_all_groups:
            detected.append({
                "vector_id": defn["vector_id"],
                "name": defn["name"],
                "severity": defn["severity"],
                "description": defn["description"]
            })

    return detected


def summarize_identity_policies(
    attached_policies: List[Dict[str, Any]],
    inline_policies: List[Dict[str, Any]],
    trust_policy: Optional[Any] = None,
    target_account_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Produces a consolidated policy intelligence summary for an IAM Role or User.
    """
    aggregated_actions: Set[str] = set()
    normalized_hashes: Dict[str, str] = {}
    has_admin_policy = False
    wildcard_admin_detected = False

    # 1. Process attached managed policies
    for pol in attached_policies:
        pol_name = pol.get("policy_name", "")
        pol_arn = pol.get("policy_arn", "")
        if pol_name == "AdministratorAccess" or "AdministratorAccess" in pol_arn:
            has_admin_policy = True
            aggregated_actions.add("*")

        doc = pol.get("policy_document")
        if doc:
            norm_doc = normalize_policy_document(doc)
            aggregated_actions.update(extract_allowed_actions(norm_doc))
            normalized_hashes[pol_name or pol_arn] = compute_policy_hash(norm_doc)
            if is_wildcard_administrator(norm_doc):
                wildcard_admin_detected = True

    # 2. Process inline policies
    for pol in inline_policies:
        pol_name = pol.get("policy_name", "inline")
        doc = pol.get("policy_document")
        if doc:
            norm_doc = normalize_policy_document(doc)
            aggregated_actions.update(extract_allowed_actions(norm_doc))
            normalized_hashes[f"inline:{pol_name}"] = compute_policy_hash(norm_doc)
            if is_wildcard_administrator(norm_doc):
                wildcard_admin_detected = True

    has_admin = has_admin_policy or wildcard_admin_detected or ("*" in aggregated_actions)

    # 3. Privilege escalation analysis
    escalation_vectors = analyze_privilege_escalation(aggregated_actions)

    # 4. Trust policy analysis (if role)
    trust_analysis = None
    if trust_policy is not None:
        trust_analysis = analyze_trust_policy(trust_policy, target_account_id=target_account_id)

    return {
        "has_administrator_access": has_admin,
        "wildcard_admin_detected": wildcard_admin_detected,
        "has_admin_policy_attached": has_admin_policy,
        "escalation_vectors": escalation_vectors,
        "trust_analysis": trust_analysis,
        "action_count": len(aggregated_actions),
        "allowed_actions": sorted(list(aggregated_actions)),
        "policy_hashes": normalized_hashes
    }
