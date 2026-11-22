"""
ExposureFence — S3 Cloud Asset Graph Analyzer & Evidence Ingestion
Ingests S3 bucket evidence into the ResourceGraph, creating S3_BUCKET, ACCOUNT,
and INTERNET nodes, and injecting strictly evidence-backed edges with confidence scores.
"""

from typing import Any, Dict, List, Optional

from backend.graph.models import EdgeType, GraphEdge, GraphNode, NodeType, RelationshipStatus


def ingest_s3_evidence_to_graph(
    evidence_list: List[Dict[str, Any]],
    graph: Any
) -> Dict[str, int]:
    """
    Ingests S3 bucket evidence records into the ResourceGraph.
    Every created edge is strictly grounded with an evidence_id and confidence rating.
    """
    nodes_added = 0
    edges_added = 0

    for ev in evidence_list:
        source_type = ev.get("source_type")
        if source_type != "AWS::S3::Bucket":
            continue

        raw = ev.get("raw_evidence", {})
        bucket_name = ev.get("resource_id", "unknown-bucket")
        bucket_arn = raw.get("bucket_arn") or f"arn:aws:s3:::{bucket_name}"
        account_id = ev.get("account_id") or raw.get("account_id") or "UNKNOWN"
        region = ev.get("region") or raw.get("region") or "UNKNOWN"
        evidence_id = ev.get("evidence_id")

        is_public = bool(raw.get("is_public", False))
        exposure_summary = raw.get("exposure_summary", {})
        encryption = raw.get("encryption", {})
        versioning = raw.get("versioning", {})
        bp = raw.get("bucket_policy", {})

        # 1. S3 Bucket Node
        bucket_node = GraphNode(
            id=bucket_arn,
            node_type=NodeType.S3_BUCKET,
            label=bucket_name,
            is_sensitive=is_public or encryption.get("is_kms", False),
            is_publicly_exposed=is_public,
            properties={
                "account_id": account_id,
                "region": region,
                "evidence_id": evidence_id,
                "is_public": is_public,
                "encryption_type": encryption.get("encryption_type"),
                "versioning_status": versioning.get("status"),
                "exposure_level": exposure_summary.get("exposure_level")
            }
        )
        graph.add_node(bucket_node)
        nodes_added += 1

        # 2. Account Node & Containment Edge
        if account_id and account_id != "UNKNOWN":
            account_node_id = f"arn:aws:organizations:::{account_id}:account"
            graph.add_node(GraphNode(
                id=account_node_id,
                node_type=NodeType.ACCOUNT,
                label=f"Account-{account_id}"
            ))
            nodes_added += 1

            graph.add_edge(GraphEdge(
                edge_id=f"edge-acct-bucket-{account_id}-{bucket_name}",
                source_id=account_node_id,
                target_id=bucket_arn,
                edge_type=EdgeType.CONTAINS,
                status=RelationshipStatus.CONFIRMED,
                evidence_id=evidence_id,
                confidence=1.0
            ))
            edges_added += 1

        # 3. Public Exposure & Internet Edge
        if is_public:
            internet_id = "INTERNET"
            graph.add_node(GraphNode(
                id=internet_id,
                node_type=NodeType.INTERNET,
                label="Public Internet"
            ))
            nodes_added += 1

            graph.add_edge(GraphEdge(
                edge_id=f"edge-internet-s3-{bucket_name}",
                source_id=internet_id,
                target_id=bucket_arn,
                edge_type=EdgeType.NETWORK_EXPOSED,
                status=RelationshipStatus.CONFIRMED,
                evidence_id=evidence_id,
                confidence=float(exposure_summary.get("confidence", 1.0)),
                properties={"reasons": exposure_summary.get("exposure_reasons", [])}
            ))
            edges_added += 1

        # 4. Cross-Account Access Edges
        for cross_p in bp.get("cross_account_principals", []):
            cross_node_id = cross_p if cross_p.startswith("arn:") else f"principal:{cross_p}"
            graph.add_node(GraphNode(
                id=cross_node_id,
                node_type=NodeType.IAM_ROLE if ":role/" in cross_p else NodeType.ACCOUNT,
                label=cross_p.split("/")[-1] if "/" in cross_p else cross_p
            ))
            nodes_added += 1

            graph.add_edge(GraphEdge(
                edge_id=f"edge-cross-s3-{bucket_name}-{cross_p.replace(':', '_').replace('/', '_')}",
                source_id=cross_node_id,
                target_id=bucket_arn,
                edge_type=EdgeType.ACCESSES_RESOURCE,
                status=RelationshipStatus.CONFIRMED,
                evidence_id=evidence_id,
                confidence=1.0
            ))
            edges_added += 1

    return {"nodes_added": nodes_added, "edges_added": edges_added}
