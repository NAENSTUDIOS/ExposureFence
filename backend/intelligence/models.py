"""
ExposureFence — Canonical Finding & Asset Inventory Models
Codifies standardized cloud security findings, asset inventory records,
and finding lifecycle enums across native connectors and multi-source engines.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
from typing import Any, Dict, List, Optional


class FindingSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class FindingStatus(str, Enum):
    NEW = "NEW"
    ACTIVE = "ACTIVE"
    SUPPRESSED = "SUPPRESSED"
    RESOLVED = "RESOLVED"
    REOPENED = "REOPENED"


class FindingSource(str, Enum):
    NATIVE_S3 = "NATIVE_S3"
    NATIVE_EC2 = "NATIVE_EC2"
    NATIVE_IAM = "NATIVE_IAM"
    SECURITY_HUB = "SECURITY_HUB"
    AWS_CONFIG = "AWS_CONFIG"
    PROWLER = "PROWLER"


@dataclass
class CanonicalFinding:
    """
    Normalized security finding schema uniting AWS native connectors,
    AWS Security Hub, AWS Config, and Prowler into a single authoritative record.
    """
    finding_id: str
    source_id: str
    source_type: FindingSource
    raw_finding_hash: str
    resource_arn: str
    account_id: str
    region: str
    service: str
    resource_type: str
    title: str
    description: str
    severity: FindingSeverity
    status: FindingStatus = FindingStatus.NEW
    first_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    suppression_reason: Optional[str] = None
    suppressed_until: Optional[str] = None
    evidence_id: Optional[str] = None
    correlation_id: Optional[str] = None
    raw_payload: Dict[str, Any] = field(default_factory=dict)
    remediation_recommendation: Optional[str] = None
    compliance_tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value if isinstance(self.severity, FindingSeverity) else str(self.severity)
        d["status"] = self.status.value if isinstance(self.status, FindingStatus) else str(self.status)
        d["source_type"] = self.source_type.value if isinstance(self.source_type, FindingSource) else str(self.source_type)
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CanonicalFinding":
        d = dict(data)
        if isinstance(d.get("severity"), str):
            d["severity"] = FindingSeverity(d["severity"])
        if isinstance(d.get("status"), str):
            d["status"] = FindingStatus(d["status"])
        if isinstance(d.get("source_type"), str):
            d["source_type"] = FindingSource(d["source_type"])
        return cls(**d)

    def compute_payload_hash(self) -> str:
        """Computes deterministic SHA-256 of canonical finding data."""
        canonical_dict = {
            "source_id": self.source_id,
            "source_type": self.source_type.value,
            "resource_arn": self.resource_arn,
            "title": self.title,
            "severity": self.severity.value,
        }
        encoded = json.dumps(canonical_dict, sort_keys=True).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


@dataclass
class AssetRecord:
    """
    Cloud Asset Inventory record representing a discovered AWS cloud resource,
    its current configuration digest, and drift status.
    """
    resource_arn: str
    account_id: str
    region: str
    service: str
    resource_type: str
    resource_id: str
    tags: Dict[str, str] = field(default_factory=dict)
    configuration_digest: str = ""
    last_scanned: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    is_active: bool = True
    drift_detected: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AssetRecord":
        return cls(**data)
