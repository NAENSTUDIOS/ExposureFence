"""
ExposureFence — Contextual Blast-Radius & Choke-Point Analysis Engine
Calculates downstream reachability from compromised nodes, quantifies data exposure impact,
and identifies single-mitigation choke points that sever multiple attack paths.
"""

from collections import Counter, deque
from typing import List, Set

from backend.graph.attack_paths import AttackPathEngine
from backend.graph.engine import ResourceGraph
from backend.graph.models import BlastRadiusResult


class BlastRadiusEngine:
    """
    Computes reachable asset boundaries and identifies architectural choke points.
    """

    def __init__(self, graph: ResourceGraph):
        self.graph = graph

    def calculate_blast_radius(self, root_node_id: str) -> BlastRadiusResult:
        """
        Calculates all reachable downstream nodes and sensitive asset impact from a given root node.
        """
        root_node = self.graph.get_node(root_node_id)
        if not root_node:
            return BlastRadiusResult(
                root_node_id=root_node_id,
                reachable_node_ids=[],
                sensitive_resource_count=0,
                cumulative_risk_impact=0.0,
                critical_choke_points=[]
            )

        visited: Set[str] = set()
        queue = deque([root_node_id])
        sensitive_count = 0
        cumulative_risk = 0.0

        while queue:
            curr_id = queue.popleft()
            if curr_id in visited:
                continue
            visited.add(curr_id)

            curr_node = self.graph.get_node(curr_id)
            if curr_node and curr_node.is_sensitive:
                sensitive_count += 1
                cumulative_risk += 35.0
            else:
                cumulative_risk += 10.0

            # Neighbors
            neighbors = self.graph.get_neighbors(curr_id, direction="out")
            for nb in neighbors:
                if nb.id not in visited:
                    queue.append(nb.id)

        # Choke point analysis
        path_engine = AttackPathEngine(self.graph)
        paths = path_engine.find_all_attack_paths(start_node_id=root_node_id)

        edge_counter: Counter = Counter()
        for p in paths:
            for e in p.edges:
                edge_counter[e.edge_id] += 1

        # Most frequent edges across attack paths are critical choke points
        critical_choke_points = [
            f"{edge_id} (appears in {count} paths)"
            for edge_id, count in edge_counter.most_common(3)
        ]

        # Exclude root from reachable list for clarity
        reachable = sorted(list(visited - {root_node_id}))

        return BlastRadiusResult(
            root_node_id=root_node_id,
            reachable_node_ids=reachable,
            sensitive_resource_count=sensitive_count,
            cumulative_risk_impact=min(100.0, cumulative_risk),
            critical_choke_points=critical_choke_points
        )
