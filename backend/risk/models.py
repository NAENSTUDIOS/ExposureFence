"""
ExposureFence — Contextual Risk Engine Models
Codifies multi-factor risk scores, explainable sub-score breakdowns, and risk acceptance lifecycle.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from backend.intelligence.models import FindingSeverity


@dataclass
class RiskScore:
    """
    Deterministic, explainable contextual risk score.
    """
    overall_score: float
    severity: FindingSeverity
    scoring_policy_version: str
    component_breakdown: Dict[str, float]
    input_evidence_ids: List[str]
    calculated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    is_accepted: bool = False
    effective_score: float = 0.0

    def __post_init__(self):
        if not self.effective_score:
            self.effective_score = 0.0 if self.is_accepted else self.overall_score

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value if isinstance(self.severity, FindingSeverity) else str(self.severity)
        return d


@dataclass
class RiskAcceptance:
    """
    Formal risk acceptance record with mandatory justification and expiration.
    """
    acceptance_id: str
    finding_id: str
    resource_arn: str
    justification: str
    approver: str
    accepted_at: str
    expires_at: str
    status: str = "ACTIVE"  # ACTIVE, EXPIRED, REVOKED

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
