"""
ExposureFence — Cloud Asset Directed Graph Engine
Maintains in-memory and SQLite-backed resource relationship graph,
indexing nodes, edges, adjacency relationships, and evidence provenance.
"""

from collections import defaultdict
from typing import Any, Dict, List, Optional

from backend.graph.models import EdgeType, GraphEdge, GraphNode, NodeType, RelationshipStatus


class ResourceGraph:
    """
    Deterministic directed graph engine modeling cloud resource relationships.
    """

    def __init__(self):
        self._nodes: Dict[str, GraphNode] = {}
        self._edges: Dict[str, GraphEdge] = {}
        self._adj_out: Dict[str, List[str]] = defaultdict(list)
        self._adj_in: Dict[str, List[str]] = defaultdict(list)

    def add_node(self, node: GraphNode) -> GraphNode:
        """Adds or updates a node in the graph."""
        self._nodes[node.id] = node
        return node

    def add_edge(self, edge: GraphEdge) -> GraphEdge:
        """Adds a directed edge from source to target."""
        self._edges[edge.edge_id] = edge
        if edge.edge_id not in self._adj_out[edge.source_id]:
            self._adj_out[edge.source_id].append(edge.edge_id)
        if edge.edge_id not in self._adj_in[edge.target_id]:
            self._adj_in[edge.target_id].append(edge.edge_id)
        return edge

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        """Retrieves a node by identifier."""
        return self._nodes.get(node_id)

    def list_nodes(self, node_type: Optional[NodeType] = None) -> List[GraphNode]:
        """Returns all nodes, optionally filtered by node_type."""
        if node_type:
            return [n for n in self._nodes.values() if n.node_type == node_type]
        return list(self._nodes.values())

    def get_edge(self, edge_id: str) -> Optional[GraphEdge]:
        """Retrieves an edge by edge_id."""
        return self._edges.get(edge_id)

    def list_edges(
        self,
        source_id: Optional[str] = None,
        target_id: Optional[str] = None,
        edge_type: Optional[EdgeType] = None
    ) -> List[GraphEdge]:
        """Returns edges filtered by source, target, or edge_type."""
        edges = list(self._edges.values())
        if source_id:
            edges = [e for e in edges if e.source_id == source_id]
        if target_id:
            edges = [e for e in edges if e.target_id == target_id]
        if edge_type:
            edges = [e for e in edges if e.edge_type == edge_type]
        return edges

    def get_neighbors(self, node_id: str, direction: str = "out") -> List[GraphNode]:
        """Returns neighboring nodes in the specified direction ('out' or 'in')."""
        if direction == "out":
            edge_ids = self._adj_out.get(node_id, [])
            neighbor_ids = [self._edges[eid].target_id for eid in edge_ids if eid in self._edges]
        else:
            edge_ids = self._adj_in.get(node_id, [])
            neighbor_ids = [self._edges[eid].source_id for eid in edge_ids if eid in self._edges]

        return [self._nodes[nid] for nid in neighbor_ids if nid in self._nodes]

    @classmethod
    def build_default_topology(cls) -> "ResourceGraph":
        """
        Builds the baseline cloud asset relationship topology for ExposureFence environments.
        Directly fulfills Scenario 1: Internet -> Public SG -> Workload -> IAM Admin Role -> Sensitive S3.
        """
        graph = cls()

        # Nodes
        internet = GraphNode(
            id="INTERNET",
            node_type=NodeType.INTERNET,
            label="Public Internet (0.0.0.0/0)",
            is_publicly_exposed=True
        )
        sg = GraphNode(
            id="sg-0123456789abcdef0",
            node_type=NodeType.SECURITY_GROUP,
            label="launch-wizard-1 (Open SSH 22)",
            properties={"open_ports": [22], "cidr": "0.0.0.0/0", "vpc_id": "vpc-0a1b2c3d"},
            is_publicly_exposed=True
        )
        instance = GraphNode(
            id="i-0fedcba9876543210",
            node_type=NodeType.EC2_INSTANCE,
            label="Production Bastion / Web Server",
            properties={"instance_type": "t3.medium", "vpc_id": "vpc-0a1b2c3d", "private_ip": "10.0.1.50"}
        )
        iam_role = GraphNode(
            id="EC2WorkloadAdminRole",
            node_type=NodeType.IAM_ROLE,
            label="EC2 Workload Instance Role",
            properties={"has_administrator_access": True, "arn": "arn:aws:iam::123456789012:role/EC2WorkloadAdminRole"}
        )
        policy = GraphNode(
            id="AdministratorAccess",
            node_type=NodeType.IAM_POLICY,
            label="AWS Managed: AdministratorAccess (*)",
            properties={"is_admin": True, "arn": "arn:aws:iam::aws:policy/AdministratorAccess"}
        )
        sensitive_s3 = GraphNode(
            id="arn:aws:s3:::corp-finance-public-export",
            node_type=NodeType.S3_BUCKET,
            label="corp-finance-public-export",
            properties={"data_classification": "Confidential", "contains_pii": True},
            is_sensitive=True,
            is_publicly_exposed=True
        )
        audit_s3 = GraphNode(
            id="arn:aws:s3:::corp-internal-audit-archive",
            node_type=NodeType.S3_BUCKET,
            label="corp-internal-audit-archive",
            properties={"data_classification": "Restricted", "contains_audit_logs": True},
            is_sensitive=True,
            is_publicly_exposed=False
        )

        for n in [internet, sg, instance, iam_role, policy, sensitive_s3, audit_s3]:
            graph.add_node(n)

        # Edges
        e1 = GraphEdge(
            edge_id="edge-net-sg",
            source_id="INTERNET",
            target_id="sg-0123456789abcdef0",
            edge_type=EdgeType.NETWORK_EXPOSED,
            status=RelationshipStatus.CONFIRMED,
            evidence_id="EV-SG-sg-0123456789abcdef0-MOCK",
            properties={"port": 22, "protocol": "tcp"}
        )
        e2 = GraphEdge(
            edge_id="edge-sg-ec2",
            source_id="sg-0123456789abcdef0",
            target_id="i-0fedcba9876543210",
            edge_type=EdgeType.MEMBER_OF,
            status=RelationshipStatus.CONFIRMED,
            properties={"association": "NetworkInterface"}
        )
        e3 = GraphEdge(
            edge_id="edge-ec2-role",
            source_id="i-0fedcba9876543210",
            target_id="EC2WorkloadAdminRole",
            edge_type=EdgeType.ASSOCIATED_ROLE,
            status=RelationshipStatus.CONFIRMED,
            properties={"profile": "InstanceProfile"}
        )
        e4 = GraphEdge(
            edge_id="edge-role-policy",
            source_id="EC2WorkloadAdminRole",
            target_id="AdministratorAccess",
            edge_type=EdgeType.GRANTS_PRIVILEGE,
            status=RelationshipStatus.CONFIRMED,
            evidence_id="EV-AWS-IAM-EC2WorkloadAdminRole-MOCK"
        )
        e5 = GraphEdge(
            edge_id="edge-policy-s3-finance",
            source_id="AdministratorAccess",
            target_id="arn:aws:s3:::corp-finance-public-export",
            edge_type=EdgeType.ACCESSES_RESOURCE,
            status=RelationshipStatus.CONFIRMED,
            properties={"actions": ["s3:*"]}
        )
        e6 = GraphEdge(
            edge_id="edge-policy-s3-audit",
            source_id="AdministratorAccess",
            target_id="arn:aws:s3:::corp-internal-audit-archive",
            edge_type=EdgeType.ACCESSES_RESOURCE,
            status=RelationshipStatus.CONFIRMED,
            properties={"actions": ["s3:*"]}
        )

        for e in [e1, e2, e3, e4, e5, e6]:
            graph.add_edge(e)

        return graph
