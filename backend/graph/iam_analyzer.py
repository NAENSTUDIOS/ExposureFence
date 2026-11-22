"""
ExposureFence — IAM Privilege Escalation & Dangerous Action Analyzer
Analyzes IAM roles, attached policies, and trust configurations for privilege escalation
vectors and dangerous permission combinations.
"""

from typing import Any, Dict, List, Optional, Set

from backend.graph.models import EdgeType, GraphEdge, GraphNode, NodeType, RelationshipStatus


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


def ingest_iam_evidence_to_graph(evidence_list: List[Dict[str, Any]], graph: Any) -> Dict[str, int]:
    """
    Ingests normalized IAM Role and User evidence records into the ResourceGraph,
    creating verified nodes and edges for:
      - Role/User -> Attached Managed Policy (GRANTS_PRIVILEGE)
      - Role/User -> Inline Policy (GRANTS_PRIVILEGE)
      - External Principal -> Role (ASSUMES_ROLE)
      - Identity -> Escalation Vector (GRANTS_PRIVILEGE)
    Guarantees every edge includes evidence_id and confidence score.
    """
    nodes_added = 0
    edges_added = 0

    for ev in evidence_list:
        source_type = ev.get("source_type")
        raw = ev.get("raw_evidence", {})
        evidence_id = ev.get("evidence_id")
        account_id = ev.get("account_id")

        if source_type == "AWS::IAM::Role":
            role_name = ev.get("resource_id", "unknown-role")
            role_arn = raw.get("role_arn") or f"arn:aws:iam::{account_id or '123456789012'}:role/{role_name}"
            has_admin = raw.get("has_administrator_access", False)

            graph.add_node(GraphNode(
                id=role_arn,
                node_type=NodeType.IAM_ROLE,
                label=role_name,
                is_sensitive=has_admin,
                properties={"account_id": account_id, "evidence_id": evidence_id}
            ))
            nodes_added += 1

            # 1. Attached Policies
            for p in raw.get("attached_policies", []):
                pol_name = p.get("policy_name", "managed-policy")
                pol_arn = p.get("policy_arn") or f"arn:aws:iam::aws:policy/{pol_name}"
                graph.add_node(GraphNode(
                    id=pol_arn,
                    node_type=NodeType.IAM_POLICY,
                    label=pol_name,
                    is_sensitive=p.get("is_admin_policy", False)
                ))
                nodes_added += 1

                graph.add_edge(GraphEdge(
                    edge_id=f"edge-role-pol-{role_name}-{pol_name}",
                    source_id=role_arn,
                    target_id=pol_arn,
                    edge_type=EdgeType.GRANTS_PRIVILEGE,
                    status=RelationshipStatus.CONFIRMED,
                    evidence_id=evidence_id,
                    confidence=1.0
                ))
                edges_added += 1

            # 2. Inline Policies
            for ip in raw.get("inline_policies", []):
                pol_name = ip.get("policy_name", "inline")
                inline_id = f"{role_arn}:inline:{pol_name}"
                graph.add_node(GraphNode(
                    id=inline_id,
                    node_type=NodeType.IAM_POLICY,
                    label=f"inline:{pol_name}"
                ))
                nodes_added += 1

                graph.add_edge(GraphEdge(
                    edge_id=f"edge-role-inline-{role_name}-{pol_name}",
                    source_id=role_arn,
                    target_id=inline_id,
                    edge_type=EdgeType.GRANTS_PRIVILEGE,
                    status=RelationshipStatus.CONFIRMED,
                    evidence_id=evidence_id,
                    confidence=1.0
                ))
                edges_added += 1

            # 3. Trust Policy / External Principals
            summary = raw.get("policy_summary", {})
            trust_analysis = summary.get("trust_analysis") or {}
            for principal in trust_analysis.get("trusted_principals", []):
                if principal == "*":
                    graph.add_edge(GraphEdge(
                        edge_id=f"edge-trust-wildcard-{role_name}",
                        source_id="INTERNET",
                        target_id=role_arn,
                        edge_type=EdgeType.ASSUMES_ROLE,
                        status=RelationshipStatus.CONFIRMED,
                        evidence_id=evidence_id,
                        confidence=0.9,
                        assumptions=["Wildcard principal allows unauthenticated assume role."]
                    ))
                    edges_added += 1
                else:
                    graph.add_node(GraphNode(
                        id=principal,
                        node_type=NodeType.ACCOUNT if "arn:" in principal else NodeType.WORKLOAD,
                        label=principal
                    ))
                    nodes_added += 1

                    graph.add_edge(GraphEdge(
                        edge_id=f"edge-trust-{principal[:16]}-{role_name}",
                        source_id=principal,
                        target_id=role_arn,
                        edge_type=EdgeType.ASSUMES_ROLE,
                        status=RelationshipStatus.CONFIRMED,
                        evidence_id=evidence_id,
                        confidence=1.0
                    ))
                    edges_added += 1

            # 4. Privilege Escalation Vectors
            for esc in summary.get("escalation_vectors", []):
                esc_id = f"ESCALATION:{esc['vector_id']}:{role_name}"
                graph.add_node(GraphNode(
                    id=esc_id,
                    node_type=NodeType.WORKLOAD,
                    label=esc["name"],
                    is_sensitive=True
                ))
                nodes_added += 1

                graph.add_edge(GraphEdge(
                    edge_id=f"edge-esc-{role_name}-{esc['vector_id']}",
                    source_id=role_arn,
                    target_id=esc_id,
                    edge_type=EdgeType.GRANTS_PRIVILEGE,
                    status=RelationshipStatus.CONFIRMED,
                    evidence_id=evidence_id,
                    confidence=0.95,
                    properties=esc
                ))
                edges_added += 1

        elif source_type == "AWS::IAM::User":
            user_name = ev.get("resource_id", "unknown-user")
            user_arn = raw.get("user_arn") or f"arn:aws:iam::{account_id or '123456789012'}:user/{user_name}"
            has_admin = raw.get("has_administrator_access", False)

            graph.add_node(GraphNode(
                id=user_arn,
                node_type=NodeType.IAM_USER,
                label=user_name,
                is_sensitive=has_admin,
                properties={"account_id": account_id, "evidence_id": evidence_id}
            ))
            nodes_added += 1

            # 1. Attached Policies
            for p in raw.get("attached_policies", []):
                pol_name = p.get("policy_name", "managed-policy")
                pol_arn = p.get("policy_arn") or f"arn:aws:iam::aws:policy/{pol_name}"
                graph.add_node(GraphNode(
                    id=pol_arn,
                    node_type=NodeType.IAM_POLICY,
                    label=pol_name,
                    is_sensitive=p.get("is_admin_policy", False)
                ))
                nodes_added += 1

                graph.add_edge(GraphEdge(
                    edge_id=f"edge-user-pol-{user_name}-{pol_name}",
                    source_id=user_arn,
                    target_id=pol_arn,
                    edge_type=EdgeType.GRANTS_PRIVILEGE,
                    status=RelationshipStatus.CONFIRMED,
                    evidence_id=evidence_id,
                    confidence=1.0
                ))
                edges_added += 1

            # 2. Inline Policies
            for ip in raw.get("inline_policies", []):
                pol_name = ip.get("policy_name", "inline")
                inline_id = f"{user_arn}:inline:{pol_name}"
                graph.add_node(GraphNode(
                    id=inline_id,
                    node_type=NodeType.IAM_POLICY,
                    label=f"inline:{pol_name}"
                ))
                nodes_added += 1

                graph.add_edge(GraphEdge(
                    edge_id=f"edge-user-inline-{user_name}-{pol_name}",
                    source_id=user_arn,
                    target_id=inline_id,
                    edge_type=EdgeType.GRANTS_PRIVILEGE,
                    status=RelationshipStatus.CONFIRMED,
                    evidence_id=evidence_id,
                    confidence=1.0
                ))
                edges_added += 1

    return {"nodes_added": nodes_added, "edges_added": edges_added}
