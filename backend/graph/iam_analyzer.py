"""
ExposureFence — IAM Privilege Escalation & Dangerous Action Analyzer
Analyzes IAM roles, attached policies, and trust configurations for privilege escalation
vectors and dangerous permission combinations.
"""

from typing import Any, Dict, List, Set


# Known AWS Privilege Escalation Vectors (Bishop Fox / Rhino Security Labs research)
ESCALATION_PATTERNS = [
    {
        "id": "ESC-01",
        "name": "Administrator Access Wildcard",
        "required_actions": [["*"]],
        "description": "Role possesses wildcard '*' on all resources, conferring root equivalent privileges.",
        "severity": "CRITICAL",
        "risk_weight": 40.0
    },
    {
        "id": "ESC-02",
        "name": "PassRole + EC2 RunInstances Escalation",
        "required_actions": [["iam:passrole"], ["ec2:runinstances"]],
        "description": "Role can pass an administrative role to a newly launched EC2 instance.",
        "severity": "HIGH",
        "risk_weight": 25.0
    },
    {
        "id": "ESC-03",
        "name": "CreatePolicyVersion Self-Escalation",
        "required_actions": [["iam:createpolicyversion", "iam:setdefaultpolicyversion"]],
        "description": "Role can author a new policy version granting itself administrator permissions.",
        "severity": "HIGH",
        "risk_weight": 25.0
    },
    {
        "id": "ESC-04",
        "name": "AttachRolePolicy Self-Escalation",
        "required_actions": [["iam:attachrolepolicy", "iam:putrolepolicy"]],
        "description": "Role can attach higher-privilege managed policies to itself or other roles.",
        "severity": "HIGH",
        "risk_weight": 25.0
    },
    {
        "id": "ESC-05",
        "name": "AssumeRole Wildcard Trust",
        "required_actions": [["sts:assumerole"]],
        "description": "Role can assume arbitrary roles across the account without strict external ID boundaries.",
        "severity": "MEDIUM",
        "risk_weight": 15.0
    },
    {
        "id": "ESC-06",
        "name": "Sensitive Data Exfiltration",
        "required_actions": [["s3:getobject", "s3:listbucket"]],
        "description": "Role can read and exfiltrate object contents from sensitive S3 buckets.",
        "severity": "HIGH",
        "risk_weight": 20.0
    }
]


class IAMPrivilegeAnalyzer:
    """Detects dangerous permission combinations and privilege escalation risks."""

    @staticmethod
    def extract_action_set(policies: List[Dict[str, Any]]) -> Set[str]:
        """Extracts and normalizes all allowed actions from a list of policy documents."""
        actions: Set[str] = set()
        for pol in policies:
            # Check attached policy name
            pol_name = pol.get("policy_name", "")
            if pol_name == "AdministratorAccess":
                actions.add("*")

            # Check statements if available
            doc = pol.get("document", {}) or pol.get("policy_document", {})
            statements = doc.get("Statement", [])
            if isinstance(statements, dict):
                statements = [statements]

            for stmt in statements:
                if stmt.get("Effect") == "Allow":
                    act = stmt.get("Action", [])
                    if isinstance(act, str):
                        act = [act]
                    for a in act:
                        actions.add(a.lower())
        return actions

    @classmethod
    def analyze_role_privileges(cls, role_record: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Analyzes an IAM role for dangerous permission combinations and escalation vectors.
        """
        attached = role_record.get("attached_policies", [])
        has_admin_flag = role_record.get("has_administrator_access", False)

        actions = cls.extract_action_set(attached)
        if has_admin_flag:
            actions.add("*")

        detected_vectors = []

        for pattern in ESCALATION_PATTERNS:
            req_groups = pattern["required_actions"]
            matched_all_groups = True

            for group in req_groups:
                # Group matches if wildcard '*' exists or any action in group matches
                if "*" in actions:
                    continue
                matched_action = any(act.lower() in actions for act in group)
                if not matched_action:
                    matched_all_groups = False
                    break

            if matched_all_groups:
                detected_vectors.append({
                    "pattern_id": pattern["id"],
                    "name": pattern["name"],
                    "severity": pattern["severity"],
                    "description": pattern["description"],
                    "risk_weight": pattern["risk_weight"]
                })

        return detected_vectors
