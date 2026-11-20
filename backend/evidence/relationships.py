"""
ExposureFence Evidence Engine Relationships Module
Binds evidence records to Findings, Proposals, and Rule Evaluations.
Enforces stale evidence protection and tampering checks prior to proposal approval.
"""

from typing import List, Optional, Tuple
import uuid

from backend.evidence.exceptions import EvidenceRelationshipError
from backend.evidence.freshness import is_evidence_stale
from backend.evidence.models import (
    EntityType,
    EvidenceRecord,
    EvidenceRelationship,
    FreshnessStatus,
    IntegrityStatus,
    RelationshipType,
)
from backend.evidence.repository import EvidenceRepository
from backend.evidence.verifier import verify_single_record


def bind_evidence_to_entity(
    evidence_id: str,
    entity_type: str,
    entity_id: str,
    bound_payload_sha256: str,
    relationship_type: str = RelationshipType.SUPPORTS.value,
    repository: Optional[EvidenceRepository] = None
) -> EvidenceRelationship:
    """
    Creates an immutable relationship binding an evidence snapshot to an entity.
    """
    repo = repository or EvidenceRepository()
    evidence = repo.get_evidence_by_id(evidence_id)
    if not evidence:
        raise EvidenceRelationshipError(f"Cannot bind: Evidence record '{evidence_id}' does not exist")

    rel_id = f"REL-{uuid.uuid4().hex[:12]}"
    rel = EvidenceRelationship(
        relationship_id=rel_id,
        evidence_id=evidence_id,
        entity_type=entity_type,
        entity_id=entity_id,
        relationship_type=relationship_type,
        bound_payload_sha256=bound_payload_sha256
    )
    return repo.store_relationship(rel)


def verify_proposal_evidence_binding(
    proposal_id: str,
    repository: Optional[EvidenceRepository] = None
) -> Tuple[bool, str, Optional[EvidenceRecord]]:
    """
    Verifies that a proposal's bound evidence is intact and fresh.
    Returns:
      (can_proceed: bool, reason: str, evidence_record: Optional[EvidenceRecord])

    Rules:
      1. Legacy proposals with no evidence binding return (True, 'LEGACY_UNBOUND', None).
      2. If evidence record is missing -> (False, 'MISSING_EVIDENCE', None).
      3. If evidence payload digest != bound digest snapshot -> (False, 'TAMPERED_BINDING', record).
      4. If single record integrity check fails -> (False, 'INTEGRITY_MISMATCH', record).
      5. If live evidence is STALE -> (False, 'STALE_EVIDENCE', record).
      6. Otherwise -> (True, 'VERIFIED_AND_FRESH', record).
    """
    repo = repository or EvidenceRepository()
    relationships = repo.get_relationships_for_entity(EntityType.PROPOSAL.value, proposal_id)

    if not relationships:
        # Legacy proposal created before Phase 4 evidence binding
        return (True, "LEGACY_UNBOUND: Proposal has no bound evidence snapshot", None)

    # Use the primary supporting relationship
    primary_rel = relationships[0]
    evidence = repo.get_evidence_by_id(primary_rel.evidence_id)
    if not evidence:
        return (False, f"MISSING_EVIDENCE: Bound evidence '{primary_rel.evidence_id}' not found in ledger", None)

    # Check that bound payload digest matches current record payload digest
    if primary_rel.bound_payload_sha256.lower() != evidence.payload_sha256.lower():
        return (
            False,
            f"TAMPERED_BINDING: Proposal bound digest {primary_rel.bound_payload_sha256[:16]}... "
            f"does not match evidence payload digest {evidence.payload_sha256[:16]}...",
            evidence
        )

    # Verify cryptographic integrity of the evidence record
    integ_status, integ_reason = verify_single_record(evidence)
    if integ_status != IntegrityStatus.VERIFIED:
        return (False, f"INTEGRITY_MISMATCH: {integ_reason}", evidence)

    # Check evidence freshness (applies to live AWS evidence)
    if is_evidence_stale(evidence):
        return (
            False,
            f"STALE_EVIDENCE: Evidence '{evidence.evidence_id}' collected at {evidence.collected_at} is STALE",
            evidence
        )

    return (True, "VERIFIED_AND_FRESH: Evidence integrity and freshness confirmed", evidence)
