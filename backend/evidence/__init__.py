"""
ExposureFence Unified Evidence & Provenance Engine (Phase 4)
Provides RFC 8785 canonicalization, SHA-256 verification, persistent append-only ledger,
W3C PROV-aligned provenance, freshness evaluation, and evidence-to-action proof chains.
"""

from backend.evidence.canonicalization import (
    CANONICALIZATION_ALGORITHM,
    CANONICALIZATION_VERSION,
    canonicalize_json,
    canonicalize_json_str,
    normalize_for_canonicalization,
)
from backend.evidence.collector import (
    collect_all_mock_evidence,
    collect_from_aws_ec2,
    collect_from_aws_iam,
    collect_from_aws_s3,
    collect_from_mock_s3,
    collect_from_mock_security_groups,
)
from backend.evidence.exceptions import (
    CanonicalizationError,
    EvidenceError,
    EvidenceFreshnessError,
    EvidenceIntegrityError,
    EvidenceNotFoundError,
    EvidenceRelationshipError,
    EvidenceSchemaValidationError,
    EvidenceTamperingError,
)
from backend.evidence.freshness import (
    evaluate_freshness,
    get_evidence_age_seconds,
    is_evidence_stale,
)
from backend.evidence.hashing import (
    GENESIS_HASH,
    HASH_ALGORITHM,
    compute_payload_digest,
    compute_record_hash,
    verify_payload_digest,
    verify_record_hash,
)
from backend.evidence.models import (
    AssessmentStatus,
    CollectionStatus,
    EntityType,
    EvidenceRecord,
    EvidenceRelationship,
    EvidenceVerificationEvent,
    FreshnessStatus,
    IntegrityStatus,
    ProvenanceInfo,
    RelationshipType,
    SourceMode,
)
from backend.evidence.provenance import (
    create_aws_provenance,
    create_mock_provenance,
    export_w3c_prov_dict,
)
from backend.evidence.relationships import (
    bind_evidence_to_entity,
    verify_proposal_evidence_binding,
)
from backend.evidence.repository import (
    EvidenceRepository,
    initialize_evidence_tables,
)
from backend.evidence.schema import (
    SCHEMA_VERSION,
    validate_evidence_record,
)
from backend.evidence.service import EvidenceService
from backend.evidence.verifier import (
    verify_full_ledger_chain,
    verify_single_record,
)

__all__ = [
    "CANONICALIZATION_ALGORITHM",
    "CANONICALIZATION_VERSION",
    "HASH_ALGORITHM",
    "GENESIS_HASH",
    "SCHEMA_VERSION",
    "SourceMode",
    "CollectionStatus",
    "IntegrityStatus",
    "FreshnessStatus",
    "AssessmentStatus",
    "EntityType",
    "RelationshipType",
    "ProvenanceInfo",
    "EvidenceRecord",
    "EvidenceRelationship",
    "EvidenceVerificationEvent",
    "EvidenceError",
    "EvidenceSchemaValidationError",
    "CanonicalizationError",
    "EvidenceIntegrityError",
    "EvidenceTamperingError",
    "EvidenceFreshnessError",
    "EvidenceNotFoundError",
    "EvidenceRelationshipError",
    "canonicalize_json",
    "canonicalize_json_str",
    "normalize_for_canonicalization",
    "compute_payload_digest",
    "compute_record_hash",
    "verify_payload_digest",
    "verify_record_hash",
    "validate_evidence_record",
    "create_mock_provenance",
    "create_aws_provenance",
    "export_w3c_prov_dict",
    "evaluate_freshness",
    "get_evidence_age_seconds",
    "is_evidence_stale",
    "initialize_evidence_tables",
    "EvidenceRepository",
    "verify_single_record",
    "verify_full_ledger_chain",
    "collect_from_mock_s3",
    "collect_from_mock_security_groups",
    "collect_from_aws_s3",
    "collect_from_aws_ec2",
    "collect_from_aws_iam",
    "bind_evidence_to_entity",
    "verify_proposal_evidence_binding",
    "EvidenceService",
]
