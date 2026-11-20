"""
ExposureFence — Phase 9 Red-Team Workstream 3: Cloud Graph Stress Testing
Adversarial test cases targeting:
- Cyclic graph topologies and infinite loop prevention
- Dense combinatorial graph cliques and BFS traversal budget enforcement
- Max paths limit enforcement
- Deep path traversal cutoff (max_depth limits)
- Complex IAM privilege escalation combinations
"""

import pytest

from backend.graph.attack_paths import AttackPathEngine
from backend.graph.engine import ResourceGraph
from backend.graph.iam_analyzer import IAMPrivilegeAnalyzer
from backend.graph.models import EdgeType, GraphEdge, GraphNode, NodeType


def test_graph_cyclic_topology_dos_prevention():
    """
    ATTACK: Adversary creates cyclic resource relationships (A -> B -> C -> A) to trigger infinite loop / DoS in BFS.
    DEFENSE: Cycle prevention logic (if next_id not in node_path) stops loops; BFS terminates cleanly.
    """
    graph = ResourceGraph()
    # Cyclic loop: INTERNET -> nodeA -> nodeB -> nodeC -> nodeA -> sensitiveTarget
    n_internet = GraphNode("INTERNET", NodeType.INTERNET, "Internet Entry", is_publicly_exposed=True)
    nA = GraphNode("nodeA", NodeType.EC2_INSTANCE, "EC2 Workload A")
    nB = GraphNode("nodeB", NodeType.IAM_ROLE, "Role B")
    nC = GraphNode("nodeC", NodeType.IAM_ROLE, "Role C")
    nTarget = GraphNode("arn:aws:s3:::target-vault", NodeType.S3_BUCKET, "Sensitive Target", is_sensitive=True)

    for n in [n_internet, nA, nB, nC, nTarget]:
        graph.add_node(n)

    # Add cycle
    graph.add_edge(GraphEdge("e_net_a", "INTERNET", "nodeA", EdgeType.NETWORK_EXPOSED))
    graph.add_edge(GraphEdge("e_a_b", "nodeA", "nodeB", EdgeType.ASSOCIATED_ROLE))
    graph.add_edge(GraphEdge("e_b_c", "nodeB", "nodeC", EdgeType.ASSUMES_ROLE))
    graph.add_edge(GraphEdge("e_c_a", "nodeC", "nodeA", EdgeType.ASSUMES_ROLE))  # Cycle back to nodeA!
    graph.add_edge(GraphEdge("e_c_tgt", "nodeC", "arn:aws:s3:::target-vault", EdgeType.ACCESSES_RESOURCE))

    engine = AttackPathEngine(graph)
    paths = engine.find_all_attack_paths(max_depth=8)

    # Must find the linear attack path to target without looping endlessly
    assert len(paths) >= 1
    p = paths[0]
    assert p.target_node_id == "arn:aws:s3:::target-vault"
    # Ensure nodeA appears only once in the sequence (no cycle repetition)
    assert p.intermediate_node_ids.count("nodeA") <= 1


def test_graph_dense_clique_resource_budget_exhaustion():
    """
    ATTACK: Dense mesh network (clique) where every node connects to every other node, causing exponential path explosion.
    DEFENSE: Resource budget (e.g. 200 traversals) halts traversal safely before memory or CPU exhaustion.
    """
    graph = ResourceGraph()
    n_internet = GraphNode("INTERNET", NodeType.INTERNET, "Entry", is_publicly_exposed=True)
    graph.add_node(n_internet)

    # Create 15 fully-interconnected intermediate nodes
    node_ids = [f"mesh_node_{i}" for i in range(15)]
    for nid in node_ids:
        graph.add_node(GraphNode(nid, NodeType.EC2_INSTANCE, f"Mesh {nid}"))

    n_target = GraphNode("arn:aws:s3:::dense-target", NodeType.S3_BUCKET, "Target", is_sensitive=True)
    graph.add_node(n_target)

    # Connect internet to first 5
    for nid in node_ids[:5]:
        graph.add_edge(GraphEdge(f"e_net_{nid}", "INTERNET", nid, EdgeType.NETWORK_EXPOSED))

    # Dense mesh: connect each node to next 3 nodes
    for i, src in enumerate(node_ids):
        for j in range(1, 4):
            tgt_idx = (i + j) % len(node_ids)
            tgt_id = node_ids[tgt_idx]
            graph.add_edge(GraphEdge(f"e_{src}_{tgt_id}", src, tgt_id, EdgeType.ROUTE_TO))

    # Connect last 3 to target
    for nid in node_ids[-3:]:
        graph.add_edge(GraphEdge(f"e_{nid}_tgt", nid, "arn:aws:s3:::dense-target", EdgeType.ACCESSES_RESOURCE))

    engine = AttackPathEngine(graph)
    # Execute with low resource budget
    paths = engine.find_all_attack_paths(resource_budget=150, max_paths=20)

    # Execution must finish in milliseconds without crashing or freezing
    assert isinstance(paths, list)
    assert len(paths) <= 20


def test_graph_max_paths_limit_enforcement():
    """
    ATTACK: Topology contains dozens of parallel pathways to a sensitive resource.
    DEFENSE: Engine stops collecting paths as soon as max_paths limit is reached.
    """
    graph = ResourceGraph()
    graph.add_node(GraphNode("INTERNET", NodeType.INTERNET, "Entry", is_publicly_exposed=True))
    target = GraphNode("arn:aws:s3:::parallel-target", NodeType.S3_BUCKET, "Target", is_sensitive=True)
    graph.add_node(target)

    # Create 40 distinct parallel paths: INTERNET -> SG_i -> Target
    for i in range(40):
        sg_id = f"sg-parallel-{i:02d}"
        graph.add_node(GraphNode(sg_id, NodeType.SECURITY_GROUP, f"SG {i}"))
        graph.add_edge(GraphEdge(f"e_net_{sg_id}", "INTERNET", sg_id, EdgeType.NETWORK_EXPOSED))
        graph.add_edge(GraphEdge(f"e_{sg_id}_tgt", sg_id, "arn:aws:s3:::parallel-target", EdgeType.ACCESSES_RESOURCE))

    engine = AttackPathEngine(graph)
    # Request at most 10 paths
    paths = engine.find_all_attack_paths(max_paths=10)

    assert len(paths) == 10


def test_graph_deep_path_traversal_cutoff():
    """
    ATTACK: A deep linear chain of 15 hops exceeds the max_depth limit.
    DEFENSE: Paths exceeding max_depth are pruned from traversal.
    """
    graph = ResourceGraph()
    graph.add_node(GraphNode("INTERNET", NodeType.INTERNET, "Entry", is_publicly_exposed=True))

    curr = "INTERNET"
    # Create chain of 15 hops
    for i in range(15):
        nxt = f"hop_{i}"
        graph.add_node(GraphNode(nxt, NodeType.IAM_ROLE, f"Hop {i}"))
        graph.add_edge(GraphEdge(f"e_{curr}_{nxt}", curr, nxt, EdgeType.ASSUMES_ROLE))
        curr = nxt

    target = GraphNode("arn:aws:s3:::deep-target", NodeType.S3_BUCKET, "Target", is_sensitive=True)
    graph.add_node(target)
    graph.add_edge(GraphEdge(f"e_{curr}_tgt", curr, "arn:aws:s3:::deep-target", EdgeType.ACCESSES_RESOURCE))

    engine = AttackPathEngine(graph)
    # Max depth is 6; 16-hop path must NOT be collected
    paths = engine.find_all_attack_paths(max_depth=6)
    assert len(paths) == 0

    # Max depth 20: 16-hop path IS collected
    paths_deep = engine.find_all_attack_paths(max_depth=20)
    assert len(paths_deep) == 1


def test_graph_iam_privilege_escalation_combinations():
    """
    ATTACK: Roles with various combination of dangerous IAM actions.
    DEFENSE: IAMPrivilegeAnalyzer detects and classifies ESC-01 through ESC-06 accurately.
    """
    def check_escalations(policy_doc):
        role_record = {"attached_policies": [{"document": policy_doc}]}
        vectors = IAMPrivilegeAnalyzer.analyze_role_privileges(role_record)
        return [v["pattern_id"] for v in vectors]

    policy_admin = {
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
    }
    assert "ESC-01" in check_escalations(policy_admin)

    policy_passrole = {
        "Statement": [{"Effect": "Allow", "Action": ["iam:PassRole", "ec2:RunInstances"], "Resource": "*"}]
    }
    assert "ESC-02" in check_escalations(policy_passrole)

    policy_version = {
        "Statement": [{"Effect": "Allow", "Action": "iam:CreatePolicyVersion", "Resource": "*"}]
    }
    assert "ESC-03" in check_escalations(policy_version)

    policy_attach = {
        "Statement": [{"Effect": "Allow", "Action": "iam:AttachRolePolicy", "Resource": "*"}]
    }
    assert "ESC-04" in check_escalations(policy_attach)

    policy_assume = {
        "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "*"}]
    }
    assert "ESC-05" in check_escalations(policy_assume)

    policy_exfil = {
        "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::sensitive-data/*"}]
    }
    assert "ESC-06" in check_escalations(policy_exfil)
