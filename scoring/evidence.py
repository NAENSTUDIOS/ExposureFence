"""
ExposureFence Evidence Registry & Backward-Compatibility Layer
Maintains legacy evidence ID mappings while bridging dynamically to the
Phase 4 Persistent Evidence Engine.
"""

from typing import Any, Optional

EVIDENCE_REGISTRY = {
    "EV-S3-001": "Public S3 bucket evidence",
    "EV-S3-002": "Private S3 bucket evidence",
    "EV-SG-001": "Open SSH security group evidence",
    "EV-SG-002": "Restricted security group evidence"
}


def evidence_exists(evidence_id: str) -> bool:
    """
    Checks if evidence exists in the static registry or the persistent Evidence Ledger.
    """
    if not evidence_id:
        return False
    if evidence_id in EVIDENCE_REGISTRY:
        return True

    # Bridge to Phase 4 Evidence Repository
    try:
        from backend.evidence.repository import EvidenceRepository
        repo = EvidenceRepository()
        rec = repo.get_evidence_by_id(evidence_id)
        return rec is not None
    except Exception:
        return False


def get_evidence(evidence_id: str) -> Optional[Any]:
    """
    Retrieves evidence description or persistent EvidenceRecord.
    """
    if not evidence_id:
        return None
    if evidence_id in EVIDENCE_REGISTRY:
        return EVIDENCE_REGISTRY[evidence_id]

    try:
        from backend.evidence.repository import EvidenceRepository
        repo = EvidenceRepository()
        return repo.get_evidence_by_id(evidence_id)
    except Exception:
        return None