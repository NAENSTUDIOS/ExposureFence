"""
ExposureFence — Rules Engine Exceptions
Typed exceptions for declarative rule validation, parsing, and evaluation.
"""


class RulesEngineError(Exception):
    """Base exception for all rules engine errors."""
    pass


class RuleSyntaxError(RulesEngineError):
    """Raised when YAML rule syntax is malformed or invalid."""
    pass


class RuleSchemaError(RulesEngineError):
    """Raised when rule definition violates the required schema."""
    pass


class RuleEvaluationError(RulesEngineError):
    """Raised when rule evaluation fails due to an unexpected execution error."""
    pass


class UnknownOperatorError(RulesEngineError):
    """Raised when an unrecognized condition operator is encountered."""
    pass


class UntrustedRuleContentError(RulesEngineError):
    """Raised when rule definition contains forbidden unsafe tags or commands."""
    pass
