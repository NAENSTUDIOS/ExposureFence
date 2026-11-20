"""
ExposureFence — Rule Schema Validation
Validates rule definitions against the ExposureFence Declarative Policy Contract.
"""

import re
from typing import List

from backend.rules.exceptions import RuleSchemaError
from backend.rules.models import OperatorType, Rule, RuleCondition


ID_PATTERN = re.compile(r"^[A-Za-z0-9_\-]+$")


def validate_rule_condition(condition: RuleCondition, rule_id: str) -> None:
    """Validates an individual rule condition."""
    if not condition.field or not isinstance(condition.field, str):
        raise RuleSchemaError(f"Rule {rule_id}: Condition 'field' must be a non-empty string.")

    if not isinstance(condition.operator, OperatorType):
        raise RuleSchemaError(f"Rule {rule_id}: Invalid operator: '{condition.operator}'.")


def validate_rule(rule: Rule) -> None:
    """Validates a Rule instance against required schema contracts."""
    if not rule.id or not isinstance(rule.id, str):
        raise RuleSchemaError("Rule 'id' must be a non-empty string.")

    if not ID_PATTERN.match(rule.id):
        raise RuleSchemaError(
            f"Rule id '{rule.id}' contains invalid characters. Must match {ID_PATTERN.pattern}"
        )

    if not rule.description or not isinstance(rule.description, str):
        raise RuleSchemaError(f"Rule {rule.id}: 'description' must be a non-empty string.")

    if not rule.allowed_action or not isinstance(rule.allowed_action, str):
        raise RuleSchemaError(f"Rule {rule.id}: 'allowed_action' must be a non-empty string.")

    if not rule.forbidden_action or not isinstance(rule.forbidden_action, str):
        raise RuleSchemaError(f"Rule {rule.id}: 'forbidden_action' must be a non-empty string.")

    if not rule.enforcement_layer or not isinstance(rule.enforcement_layer, str):
        raise RuleSchemaError(f"Rule {rule.id}: 'enforcement_layer' must be a non-empty string.")

    if not rule.test_id or not isinstance(rule.test_id, str):
        raise RuleSchemaError(f"Rule {rule.id}: 'test_id' must be a non-empty string.")

    if not ID_PATTERN.match(rule.test_id):
        raise RuleSchemaError(
            f"Rule {rule.id}: test_id '{rule.test_id}' must match {ID_PATTERN.pattern}"
        )

    if not rule.proof or not isinstance(rule.proof, str):
        raise RuleSchemaError(f"Rule {rule.id}: 'proof' must be a non-empty string.")

    for cond in rule.conditions:
        validate_rule_condition(cond, rule.id)


def validate_rules_collection(rules: List[Rule]) -> None:
    """Validates an entire list of rules for schema compliance and unique IDs."""
    seen_ids = set()
    for rule in rules:
        validate_rule(rule)
        if rule.id in seen_ids:
            raise RuleSchemaError(f"Duplicate rule ID detected: '{rule.id}'")
        seen_ids.add(rule.id)
