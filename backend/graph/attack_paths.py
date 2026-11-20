"""
ExposureFence — Deterministic Attack-Path Discovery Engine
Finds multi-step attack chains traversing from entry points (Public Internet, exposed SGs)
through intermediate workloads and IAM privilege escalations to sensitive target resources.
"""

from collections import deque
import hashlib
from typing import List, Optional, Set

from backend.graph.engine import ResourceGraph
from backend.graph.models import AttackPath, GraphEdge, GraphNode, NodeType


class AttackPathEngine:
    """
    Discovers, evaluates, and prioritizes attack paths across the cloud asset relationship graph.
    """

    def __init__(self, graph: ResourceGraph):
        self.graph = graph

    def find_all_attack_paths(
        self,
        start_node_id: Optional[str] = None,
        max_depth: int = 8,
        max_paths: int = 50,
        resource_budget: int = 1000
    ) -> List[AttackPath]:
        """
        Discovers all attack paths from public entry points to sensitive resources.
        Enforces explicit max_depth, max_paths limit, and resource_budget to prevent
        exponential path explosion or denial-of-service on dense/adversarial graphs.
        """
        # Determine starting nodes
        if start_node_id:
            start_nodes = [self.graph.get_node(start_node_id)]
        else:
            # All publicly exposed nodes or INTERNET
            start_nodes = [
                n for n in self.graph.list_nodes()
                if n.is_publicly_exposed or n.node_type == NodeType.INTERNET
            ]

        # Target nodes: all marked sensitive
        sensitive_nodes = {n.id for n in self.graph.list_nodes() if n.is_sensitive}

        discovered_paths: List[AttackPath] = []
        path_counter = 1

        for s_node in start_nodes:
            if not s_node:
                continue

            if len(discovered_paths) >= max_paths:
                break

            # BFS queue stores (current_node_id, [visited_node_ids], [edges_traversed])
            queue = deque([(s_node.id, [s_node.id], [])])
            traversals = 0

            while queue:
                if len(discovered_paths) >= max_paths:
                    break

                traversals += 1
                if traversals > resource_budget:
                    # Resource budget exhausted; break to protect engine availability
                    break

                curr_id, node_path, edge_path = queue.popleft()

                if len(node_path) > max_depth:
                    continue

                # If reached a sensitive node and path length > 1
                if curr_id in sensitive_nodes and len(node_path) > 1:
                    path_id = f"PATH-{path_counter:02d}-{s_node.id[:4]}-{curr_id[:6]}"
                    path_counter += 1

                    # Compute path confidence and risk
                    confidence = 1.0
                    for e in edge_path:
                        confidence *= e.confidence

                    # Risk based on target sensitivity and path depth
                    base_risk = 85.0
                    if any("AdministratorAccess" in nid for nid in node_path):
                        base_risk = 95.0
                    risk_score = min(100.0, base_risk * confidence)

                    # Controls based on intermediate nodes
                    controls = []
                    for e in edge_path:
                        if e.edge_type.value == "NETWORK_EXPOSED":
                            controls.append(f"Restrict network exposure on {e.target_id}")
                        elif e.edge_type.value == "ASSOCIATED_ROLE":
                            controls.append(f"Scope down IAM permissions on role {e.target_id}")
                        elif e.edge_type.value == "GRANTS_PRIVILEGE":
                            controls.append(f"Detach high-privilege policy {e.target_id}")

                    discovered_paths.append(AttackPath(
                        path_id=path_id,
                        start_node_id=s_node.id,
                        intermediate_node_ids=node_path[1:-1],
                        target_node_id=curr_id,
                        edges=edge_path,
                        risk_score=round(risk_score, 1),
                        confidence=round(confidence, 2),
                        required_assumptions=["Attacker achieves remote code execution or initial network access"],
                        recommended_controls=list(dict.fromkeys(controls))  # Deduplicate preserving order
                    ))
                    # Continue search to find alternative branches

                # Traverse outgoing edges
                out_edges = self.graph.list_edges(source_id=curr_id)
                for edge in out_edges:
                    next_id = edge.target_id
                    if next_id not in node_path:  # Prevent cycles
                        queue.append((next_id, node_path + [next_id], edge_path + [edge]))

        # Sort paths by risk score descending
        discovered_paths.sort(key=lambda p: p.risk_score, reverse=True)
        return discovered_paths
