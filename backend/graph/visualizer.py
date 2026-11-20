"""
ExposureFence — Graph Visualization Formatter
Converts ResourceGraph topology into Cytoscape.js / D3 compatible JSON for interactive rendering.
"""

from typing import Any, Dict, List

from backend.graph.engine import ResourceGraph
from backend.graph.models import AttackPath


class GraphVisualizer:
    """Formats ResourceGraph data into standard interactive frontend graph models."""

    @staticmethod
    def to_cytoscape_elements(graph: ResourceGraph, highlighted_path: AttackPath = None) -> List[Dict[str, Any]]:
        """
        Exports graph nodes and edges as Cytoscape.js element objects.
        """
        elements: List[Dict[str, Any]] = []

        path_node_ids = set()
        path_edge_ids = set()
        if highlighted_path:
            path_node_ids.add(highlighted_path.start_node_id)
            path_node_ids.update(highlighted_path.intermediate_node_ids)
            path_node_ids.add(highlighted_path.target_node_id)
            for e in highlighted_path.edges:
                path_edge_ids.add(e.edge_id)

        # Nodes
        for node in graph.list_nodes():
            classes = [node.node_type.value.lower()]
            if node.is_sensitive:
                classes.append("sensitive")
            if node.is_publicly_exposed:
                classes.append("exposed")
            if node.id in path_node_ids:
                classes.append("highlighted-path")

            elements.append({
                "group": "nodes",
                "data": {
                    "id": node.id,
                    "label": node.label,
                    "type": node.node_type.value,
                    "is_sensitive": node.is_sensitive,
                    "is_exposed": node.is_publicly_exposed
                },
                "classes": " ".join(classes)
            })

        # Edges
        for edge in graph.list_edges():
            classes = [edge.edge_type.value.lower()]
            if edge.edge_id in path_edge_ids:
                classes.append("highlighted-path")

            elements.append({
                "group": "edges",
                "data": {
                    "id": edge.edge_id,
                    "source": edge.source_id,
                    "target": edge.target_id,
                    "label": edge.edge_type.value,
                    "status": edge.status.value,
                    "confidence": edge.confidence
                },
                "classes": " ".join(classes)
            })

        return elements
