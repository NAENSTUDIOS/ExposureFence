"""
ExposureFence — Cloud Asset Graph Models
Defines node types, edge types, relationship statuses, attack path structures,
and blast radius models for deterministic graph analysis.
"""

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class NodeType(str, Enum):
    INTERNET = "INTERNET"
    ACCOUNT = "ACCOUNT"
    REGION = "REGION"
    VPC = "VPC"
    SUBNET = "SUBNET"
    SECURITY_GROUP = "SECURITY_GROUP"
    EC2_INSTANCE = "EC2_INSTANCE"
    IAM_ROLE = "IAM_ROLE"
    IAM_POLICY = "IAM_POLICY"
    S3_BUCKET = "S3_BUCKET"
    DATABASE = "DATABASE"
    WORKLOAD = "WORKLOAD"


class EdgeType(str, Enum):
    CONTAINS = "CONTAINS"
    MEMBER_OF = "MEMBER_OF"
    NETWORK_EXPOSED = "NETWORK_EXPOSED"
    ROUTE_TO = "ROUTE_TO"
    ASSOCIATED_ROLE = "ASSOCIATED_ROLE"
    GRANTS_PRIVILEGE = "GRANTS_PRIVILEGE"
    ASSUMES_ROLE = "ASSUMES_ROLE"
    ACCESSES_RESOURCE = "ACCESSES_RESOURCE"


class RelationshipStatus(str, Enum):
    CONFIRMED = "CONFIRMED"
    INFERRED = "INFERRED"
    UNKNOWN = "UNKNOWN"
    MISSING_EVIDENCE = "MISSING_EVIDENCE"


@dataclass
class GraphNode:
    id: str
    node_type: NodeType
    label: str
    properties: Dict[str, Any] = field(default_factory=dict)
    is_sensitive: bool = False
    is_publicly_exposed: bool = False

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["node_type"] = self.node_type.value if isinstance(self.node_type, NodeType) else str(self.node_type)
        return d


@dataclass
class GraphEdge:
    edge_id: str
    source_id: str
    target_id: str
    edge_type: EdgeType
    status: RelationshipStatus = RelationshipStatus.CONFIRMED
    evidence_id: Optional[str] = None
    properties: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0
    assumptions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["edge_type"] = self.edge_type.value if isinstance(self.edge_type, EdgeType) else str(self.edge_type)
        d["status"] = self.status.value if isinstance(self.status, RelationshipStatus) else str(self.status)
        return d


@dataclass
class AttackPath:
    path_id: str
    start_node_id: str
    intermediate_node_ids: List[str]
    target_node_id: str
    edges: List[GraphEdge]
    risk_score: float
    confidence: float
    required_assumptions: List[str] = field(default_factory=list)
    recommended_controls: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path_id": self.path_id,
            "start_node_id": self.start_node_id,
            "intermediate_node_ids": self.intermediate_node_ids,
            "target_node_id": self.target_node_id,
            "edges": [e.to_dict() for e in self.edges],
            "risk_score": self.risk_score,
            "confidence": self.confidence,
            "required_assumptions": self.required_assumptions,
            "recommended_controls": self.recommended_controls
        }


@dataclass
class BlastRadiusResult:
    root_node_id: str
    reachable_node_ids: List[str]
    sensitive_resource_count: int
    cumulative_risk_impact: float
    critical_choke_points: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
