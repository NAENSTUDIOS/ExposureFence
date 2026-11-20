"""
ExposureFence — Rules Engine Data Models
Defines dataclasses and enums for declarative rules, conditions, and evaluation results.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class RuleSeverity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RuleType(str, Enum):
    INVARIANT_TEST = "INVARIANT_TEST"
    RESOURCE_COMPLIANCE = "RESOURCE_COMPLIANCE"
    SYSTEM_GUARDRAIL = "SYSTEM_GUARDRAIL"


class RuleEnforcementLayer(str, Enum):
    APPLICATION_BOUNDARY = "Application Boundary"
    TOOL_SURFACE = "Tool Surface"
    DISPATCHER = "Dispatcher"
    PROPOSAL_SERVICE = "Proposal Service"
    AUTHENTICATION = "Authentication"
    VALIDATION = "Validation"
    SCORING_ENGINE = "Scoring Engine"
    CLOUD_RESOURCE = "Cloud Resource"


class OperatorType(str, Enum):
    EQUALS = "EQUALS"
    NOT_EQUALS = "NOT_EQUALS"
    CONTAINS = "CONTAINS"
    NOT_CONTAINS = "NOT_CONTAINS"
    STARTS_WITH = "STARTS_WITH"
    ENDS_WITH = "ENDS_WITH"
    CIDR_IN = "CIDR_IN"
    PORT_IN = "PORT_IN"
    NOT_CONTAINS_OPEN_PORT = "NOT_CONTAINS_OPEN_PORT"
    IN_LIST = "IN_LIST"
    NOT_IN_LIST = "NOT_IN_LIST"
    COUNT_EQUALS = "COUNT_EQUALS"
    COUNT_GREATER_THAN = "COUNT_GREATER_THAN"
    COUNT_LESS_THAN = "COUNT_LESS_THAN"
    FIELD_EXISTS = "FIELD_EXISTS"
    FIELD_MISSING = "FIELD_MISSING"
    REGEX_MATCH = "REGEX_MATCH"
    EVIDENCE_VERIFIED = "EVIDENCE_VERIFIED"


@dataclass
class RuleCondition:
    field: str
    operator: OperatorType
    expected_value: Any
    description: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "field": self.field,
            "operator": self.operator.value if isinstance(self.operator, OperatorType) else str(self.operator),
            "expected_value": self.expected_value,
            "description": self.description,
        }


@dataclass
class Rule:
    id: str
    description: str
    allowed_action: str
    forbidden_action: str
    enforcement_layer: str
    test_id: str
    proof: str
    severity: RuleSeverity = RuleSeverity.HIGH
    rule_type: RuleType = RuleType.INVARIANT_TEST
    target_resource_type: Optional[str] = None
    conditions: List[RuleCondition] = field(default_factory=list)
    remediation_template: Optional[str] = None
    version: str = "1.0.0"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "description": self.description,
            "allowed_action": self.allowed_action,
            "forbidden_action": self.forbidden_action,
            "enforcement_layer": self.enforcement_layer,
            "test_id": self.test_id,
            "proof": self.proof,
            "severity": self.severity.value if isinstance(self.severity, RuleSeverity) else str(self.severity),
            "rule_type": self.rule_type.value if isinstance(self.rule_type, RuleType) else str(self.rule_type),
            "target_resource_type": self.target_resource_type,
            "conditions": [c.to_dict() for c in self.conditions],
            "remediation_template": self.remediation_template,
            "version": self.version,
        }


@dataclass
class RuleEvaluationResult:
    rule_id: str
    status: str  # "PASS" | "FAIL" | "ERROR"
    test_id: str
    details: str
    severity: str
    executed_proof: str
    violations: List[str] = field(default_factory=list)
    evidence_id: Optional[str] = None
    evaluated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "status": self.status,
            "test_id": self.test_id,
            "details": self.details,
            "severity": self.severity,
            "executed_proof": self.executed_proof,
            "violations": self.violations,
            "evidence_id": self.evidence_id,
            "evaluated_at": self.evaluated_at,
        }
