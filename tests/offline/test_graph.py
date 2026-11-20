"""
ExposureFence — Cloud Asset Graph & Attack-Path Intelligence Test Suite
Tests graph topology construction, IAM escalation analysis, deterministic attack-path discovery
(Scenario 1), blast-radius computation, choke-point detection, and visualization exports.
"""

import pytest

from backend.graph.attack_paths import AttackPathEngine
from backend.graph.blast_radius import BlastRadiusEngine
from backend.graph.engine import ResourceGraph
from backend.graph.iam_analyzer import IAMPrivilegeAnalyzer
from backend.graph.models import EdgeType, GraphEdge, GraphNode, NodeType, RelationshipStatus
from backend.graph.visualizer import GraphVisualizer


def test_graph_node_and_edge_management():
    graph = ResourceGraph()
    n1 = GraphNode(id="node-1", node_type=NodeType.VPC, label="Main VPC")
    n2 = GraphNode(id="node-2", node_type=NodeType.SUBNET, label="Public Subnet")
    graph.add_node(n1)
    graph.add_node(n2)

    e1 = GraphEdge(
        edge_id="e-vpc-subnet",
        source_id="node-1",
        target_id="node-2",
        edge_type=EdgeType.CONTAINS,
        status=RelationshipStatus.CONFIRMED
    )
    graph.add_edge(e1)

    assert graph.get_node("node-1") is not None
    assert graph.get_node("node-2") is not None
    assert len(graph.list_nodes()) == 2

    # Neighbors
    out_neighbors = graph.get_neighbors("node-1", direction="out")
    assert len(out_neighbors) == 1
    assert out_neighbors[0].id == "node-2"

    in_neighbors = graph.get_neighbors("node-2", direction="in")
    assert len(in_neighbors) == 1
    assert in_neighbors[0].id == "node-1"


def test_iam_privilege_analyzer_admin_wildcard():
    role_record = {
        "role_name": "AdminRole",
        "has_administrator_access": True,
        "attached_policies": [{"policy_name": "AdministratorAccess"}]
    }
    vectors = IAMPrivilegeAnalyzer.analyze_role_privileges(role_record)
    assert len(vectors) >= 1
    assert any(v["pattern_id"] == "ESC-01" for v in vectors)


def test_iam_privilege_analyzer_passrole_escalation():
    role_record = {
        "role_name": "DevOpsRole",
        "has_administrator_access": False,
        "attached_policies": [
            {
                "policy_name": "CustomDevOpsPolicy",
                "document": {
                    "Statement": [
                        {"Effect": "Allow", "Action": ["iam:PassRole", "ec2:RunInstances"], "Resource": "*"}
                    ]
                }
            }
        ]
    }
    vectors = IAMPrivilegeAnalyzer.analyze_role_privileges(role_record)
    assert any(v["pattern_id"] == "ESC-02" for v in vectors)


def test_scenario_1_attack_path_discovery():
    """
    Scenario 1 Verification:
    Public exposure to privileged identity:
    Internet -> SG -> EC2 Instance -> IAM Admin Role -> Sensitive S3 Bucket.
    """
    graph = ResourceGraph.build_default_topology()
    path_engine = AttackPathEngine(graph)
    paths = path_engine.find_all_attack_paths()

    assert len(paths) >= 2
    # Verify top path reaches the sensitive finance bucket
    top_path = paths[0]
    assert top_path.start_node_id == "INTERNET"
    assert "sg-0123456789abcdef0" in top_path.intermediate_node_ids
    assert "i-0fedcba9876543210" in top_path.intermediate_node_ids
    assert "EC2WorkloadAdminRole" in top_path.intermediate_node_ids
    assert top_path.risk_score >= 90.0
    assert len(top_path.recommended_controls) >= 2


def test_blast_radius_and_choke_point_calculation():
    graph = ResourceGraph.build_default_topology()
    blast_engine = BlastRadiusEngine(graph)

    # Calculate blast radius if the EC2 workload is compromised
    res = blast_engine.calculate_blast_radius("i-0fedcba9876543210")
    assert res.root_node_id == "i-0fedcba9876543210"
    assert "EC2WorkloadAdminRole" in res.reachable_node_ids
    assert "AdministratorAccess" in res.reachable_node_ids
    assert "arn:aws:s3:::corp-finance-public-export" in res.reachable_node_ids
    assert res.sensitive_resource_count >= 2
    assert res.cumulative_risk_impact >= 80.0
    assert len(res.critical_choke_points) >= 1


def test_cytoscape_visualization_export():
    graph = ResourceGraph.build_default_topology()
    elements = GraphVisualizer.to_cytoscape_elements(graph)
    assert len(elements) > 10

    # Ensure nodes and edges are both present
    nodes = [e for e in elements if e.get("group") == "nodes"]
    edges = [e for e in elements if e.get("group") == "edges"]
    assert len(nodes) == 7
    assert len(edges) == 6
