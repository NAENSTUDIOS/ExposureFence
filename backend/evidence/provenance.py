"""
ExposureFence Evidence Engine Provenance Module
Implements W3C PROV-aligned provenance tracing for evidence collection activities,
entities, and agents.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from backend.evidence.models import EvidenceRecord, ProvenanceInfo


def create_mock_provenance(
    fixture_path: str,
    fixture_sha256: str,
    collector_identity: str = "ExposureFenceMockCollector/1.0",
    activity_id: Optional[str] = None
) -> ProvenanceInfo:
    """
    Creates provenance metadata for synthetic mock fixture evidence snapshots.
    """
    act_id = activity_id or f"ACT-MOCK-{uuid.uuid4().hex[:12]}"
    return ProvenanceInfo(
        source_reference=fixture_path,
        collection_activity_id=act_id,
        collector_identity=collector_identity,
        source_payload_digest=fixture_sha256,
        parent_evidence_ids=[]
    )


def create_aws_provenance(
    service_name: str,
    api_operation: str,
    collector_identity: str = "ExposureFenceAWSReadOnlyCollector/1.0",
    account_id: Optional[str] = None,
    region: Optional[str] = None,
    activity_id: Optional[str] = None
) -> ProvenanceInfo:
    """
    Creates provenance metadata for read-only AWS API collection snapshots.
    """
    act_id = activity_id or f"ACT-AWS-{service_name.upper()}-{uuid.uuid4().hex[:12]}"
    source_ref = f"aws://{account_id or 'unknown'}/{region or 'global'}/{service_name}/{api_operation}"
    return ProvenanceInfo(
        source_reference=source_ref,
        collection_activity_id=act_id,
        collector_identity=collector_identity,
        source_payload_digest=None,
        parent_evidence_ids=[]
    )


def export_w3c_prov_dict(record: EvidenceRecord) -> Dict[str, Any]:
    """
    Exports a structured W3C PROV representation of the evidence lifecycle.
    Maps:
      Entity: The evidence snapshot (record.evidence_id)
      Activity: The collection operation (provenance.collection_activity_id)
      Agent: The collector identity (provenance.collector_identity)
    """
    entity_id = f"prov:entity:{record.evidence_id}"
    activity_id = f"prov:activity:{record.provenance.collection_activity_id}"
    agent_id = f"prov:agent:{record.provenance.collector_identity}"

    return {
        "entity": {
            entity_id: {
                "prov:type": record.evidence_type,
                "exposurefence:resource_id": record.resource_id,
                "exposurefence:source_mode": record.source_mode,
                "exposurefence:payload_sha256": record.payload_sha256,
                "exposurefence:record_hash": record.record_hash,
                "exposurefence:collected_at": record.collected_at
            }
        },
        "activity": {
            activity_id: {
                "prov:type": "exposurefence:CollectionActivity",
                "prov:startTime": record.collected_at,
                "exposurefence:source_reference": record.provenance.source_reference
            }
        },
        "agent": {
            agent_id: {
                "prov:type": "prov:SoftwareAgent",
                "exposurefence:collector_name": record.collector_name,
                "exposurefence:collector_version": record.collector_version
            }
        },
        "wasGeneratedBy": {
            f"_:wgb_{record.evidence_id}": {
                "prov:entity": entity_id,
                "prov:activity": activity_id,
                "prov:time": record.collected_at
            }
        },
        "wasAttributedTo": {
            f"_:wat_{record.evidence_id}": {
                "prov:entity": entity_id,
                "prov:agent": agent_id
            }
        },
        "wasAssociatedWith": {
            f"_:waw_{record.evidence_id}": {
                "prov:activity": activity_id,
                "prov:agent": agent_id
            }
        }
    }
