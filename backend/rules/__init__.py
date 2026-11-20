"""
ExposureFence — Rules Engine Package
Public exports for the YAML-driven declarative rules engine.
"""

from backend.rules.exceptions import (
    RuleEvaluationError,
    RulesEngineError,
    RuleSchemaError,
    RuleSyntaxError,
    UnknownOperatorError,
    UntrustedRuleContentError,
)
from backend.rules.models import (
    OperatorType,
    Rule,
    RuleCondition,
    RuleEnforcementLayer,
    RuleEvaluationResult,
    RuleSeverity,
    RuleType,
)
from backend.rules.parser import load_rules_from_yaml, safe_load_yaml
from backend.rules.service import RulesEngine


__all__ = [
    "RulesEngine",
    "Rule",
    "RuleCondition",
    "RuleEvaluationResult",
    "RuleSeverity",
    "RuleType",
    "RuleEnforcementLayer",
    "OperatorType",
    "load_rules_from_yaml",
    "safe_load_yaml",
    "RulesEngineError",
    "RuleSyntaxError",
    "RuleSchemaError",
    "RuleEvaluationError",
    "UnknownOperatorError",
    "UntrustedRuleContentError",
]
