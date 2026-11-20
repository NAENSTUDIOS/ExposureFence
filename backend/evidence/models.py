"""
ExposureFence Evidence Engine Data Models
Defines typed enums, data contracts, and dataclasses for evidence records,
provenance tracking, relationships, and verification events.
"""

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class SourceMode(str, Enum):
    MOCK = "MOCK"
    AWS_READ_ONLY = "AWS_READ_ONLY"


class CollectionStatus(str, Enum):
    COLLECTED = "COLLECTED"
    PARTIAL = "PARTIAL"
    ERROR = "ERROR"


class IntegrityStatus(str, Enum):
    VERIFIED = "VERIFIED"
    INTEGRITY_MISMATCH = "INTEGRITY_MISMATCH"
    UNVERIFIABLE = "UNVERIFIABLE"


class FreshnessStatus(str, Enum):
    FRESH = "FRESH"
    STALE = "STALE"
    STATIC_FIXTURE = "STATIC_FIXTURE"
    UNKNOWN = "UNKNOWN"


class AssessmentStatus(str, Enum):
    EXPOSURE_DETECTED = "EXPOSURE_DETECTED"
    NO_ISSUE_IDENTIFIED_IN_SUPPLIED_EVIDENCE = "NO_ISSUE_IDENTIFIED_IN_SUPPLIED_EVIDENCE"
    NOT_ASSESSED = "NOT_ASSESSED"
    ERROR = "ERROR"


class EntityType(str, Enum):
    FINDING = "FINDING"
    PROPOSAL = "PROPOSAL"
    RULE_EVALUATION = "RULE_EVALUATION"


class RelationshipType(str, Enum):
    SUPPORTS = "SUPPORTS"
    DERIVED_FROM = "DERIVED_FROM"
    VALIDATES = "VALIDATES"


@dataclass
class ProvenanceInfo:
    """W3C PROV-aligned provenance metadata."""
    source_reference: str
    collection_activity_id: str
    collector_identity: str
    source_payload_digest: Optional[str] = None
    parent_evidence_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ProvenanceInfo":
        return cls(
            source_reference=data.get("source_reference", ""),
            collection_activity_id=data.get("collection_activity_id", ""),
            collector_identity=data.get("collector_identity", "ExposureFenceCollector"),
            source_payload_digest=data.get("source_payload_digest"),
            parent_evidence_ids=data.get("parent_evidence_ids", []) or []
        )


@dataclass
class EvidenceRecord:
    """Unified, versioned, immutable snapshot of security evidence."""
    # Identity
    evidence_id: str
    schema_version: str = "1.0.0"
    evidence_type: str = "CONFIGURATION_SNAPSHOT"

    # Source
    source_mode: str = SourceMode.MOCK.value
    source_provider: str = "AWS"
    source_service: str = "s3"
    source_type: str = "AWS::S3::Bucket"
    collector_name: str = "ExposureFenceCollector"
    collector_version: str = "1.0.0"

    # Resource
    resource_id: str = ""
    resource_type: str = ""
    account_id: Optional[str] = None
    region: Optional[str] = None
    resource_arn: Optional[str] = None

    # Timestamps
    collected_at: str = ""
    observed_at: Optional[str] = None
    source_created_at: Optional[str] = None
    source_updated_at: Optional[str] = None

    # Provenance
    provenance: ProvenanceInfo = field(default_factory=lambda: ProvenanceInfo("", "", ""))

    # Evidence payload
    raw_evidence: Dict[str, Any] = field(default_factory=dict)
    normalized_evidence: Dict[str, Any] = field(default_factory=dict)
    payload_sha256: str = ""

    # Cryptographic metadata
    canonicalization_algorithm: str = "RFC-8785"
    canonicalization_version: str = "1.0"
    hash_algorithm: str = "SHA-256"
    previous_record_hash: str = "0" * 64
    record_hash: str = ""

    # Verification state (distinct dimensions)
    collection_status: str = CollectionStatus.COLLECTED.value
    integrity_status: str = IntegrityStatus.VERIFIED.value
    freshness_status: str = FreshnessStatus.STATIC_FIXTURE.value
    assessment_status: str = AssessmentStatus.NOT_ASSESSED.value

    sequence_id: Optional[int] = None
    created_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        if isinstance(self.provenance, ProvenanceInfo):
            d["provenance"] = self.provenance.to_dict()
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EvidenceRecord":
        prov_data = data.get("provenance", {})
        prov_obj = prov_data if isinstance(prov_data, ProvenanceInfo) else ProvenanceInfo.from_dict(prov_data or {})

        return cls(
            evidence_id=data["evidence_id"],
            schema_version=data.get("schema_version", "1.0.0"),
            evidence_type=data.get("evidence_type", "CONFIGURATION_SNAPSHOT"),
            source_mode=data.get("source_mode", SourceMode.MOCK.value),
            source_provider=data.get("source_provider", "AWS"),
            source_service=data.get("source_service", ""),
            source_type=data.get("source_type", ""),
            collector_name=data.get("collector_name", "ExposureFenceCollector"),
            collector_version=data.get("collector_version", "1.0.0"),
            resource_id=data.get("resource_id", ""),
            resource_type=data.get("resource_type", ""),
            account_id=data.get("account_id"),
            region=data.get("region"),
            resource_arn=data.get("resource_arn"),
            collected_at=data.get("collected_at", ""),
            observed_at=data.get("observed_at"),
            source_created_at=data.get("source_created_at"),
            source_updated_at=data.get("source_updated_at"),
            provenance=prov_obj,
            raw_evidence=data.get("raw_evidence", {}) or {},
            normalized_evidence=data.get("normalized_evidence", {}) or {},
            payload_sha256=data.get("payload_sha256", ""),
            canonicalization_algorithm=data.get("canonicalization_algorithm", "RFC-8785"),
            canonicalization_version=data.get("canonicalization_version", "1.0"),
            hash_algorithm=data.get("hash_algorithm", "SHA-256"),
            previous_record_hash=data.get("previous_record_hash", "0" * 64),
            record_hash=data.get("record_hash", ""),
            collection_status=data.get("collection_status", CollectionStatus.COLLECTED.value),
            integrity_status=data.get("integrity_status", IntegrityStatus.VERIFIED.value),
            freshness_status=data.get("freshness_status", FreshnessStatus.STATIC_FIXTURE.value),
            assessment_status=data.get("assessment_status", AssessmentStatus.NOT_ASSESSED.value),
            sequence_id=data.get("sequence_id"),
            created_at=data.get("created_at")
        )


@dataclass
class EvidenceRelationship:
    """Immutable link binding an evidence record to an entity (finding, proposal, rule)."""
    relationship_id: str
    evidence_id: str
    entity_type: str
    entity_id: str
    relationship_type: str = RelationshipType.SUPPORTS.value
    bound_payload_sha256: str = ""
    created_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EvidenceRelationship":
        return cls(
            relationship_id=data["relationship_id"],
            evidence_id=data["evidence_id"],
            entity_type=data["entity_type"],
            entity_id=data["entity_id"],
            relationship_type=data.get("relationship_type", RelationshipType.SUPPORTS.value),
            bound_payload_sha256=data.get("bound_payload_sha256", ""),
            created_at=data.get("created_at", "")
        )


@dataclass
class EvidenceVerificationEvent:
    """Historical verification event appended during an integrity or freshness evaluation."""
    verification_id: str
    evidence_id: str
    checked_at: str
    integrity_status: str
    freshness_status: str
    verification_reason: str
    verifier_version: str = "1.0.0"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EvidenceVerificationEvent":
        return cls(
            verification_id=data["verification_id"],
            evidence_id=data["evidence_id"],
            checked_at=data["checked_at"],
            integrity_status=data["integrity_status"],
            freshness_status=data["freshness_status"],
            verification_reason=data.get("verification_reason", ""),
            verifier_version=data.get("verifier_version", "1.0.0")
        )
