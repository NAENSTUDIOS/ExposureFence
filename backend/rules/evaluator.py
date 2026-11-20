"""
ExposureFence — Deterministic Rule Evaluator
Executes invariant proof verification for system rules (R01-R07) and evaluates
declarative conditions on evidence records.
"""

from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from backend.rules.models import (
    OperatorType,
    Rule,
    RuleCondition,
    RuleEvaluationResult,
    RuleType,
)
from backend.rules.operators import evaluate_operator, resolve_field_path


# Registry mapping system attack tests (T01-T07) to verifying callables
_TEST_REGISTRY: Dict[str, Callable[[], None]] = {}


def _get_test_callable(test_id: str) -> Optional[Callable[[], None]]:
    """Lazily loads test functions to prevent circular import issues."""
    global _TEST_REGISTRY
    if not _TEST_REGISTRY:
        try:
            from tests.offline import test_attack_suite
            _TEST_REGISTRY = {
                "T01": test_attack_suite.test_t01_prompt_injection,
                "T02": test_attack_suite.test_t02_resource_modification,
                "T03": test_attack_suite.test_t03_privilege_escalation,
                "T04": test_attack_suite.test_t04_data_exfiltration,
                "T05": test_attack_suite.test_t05_fake_approval,
                "T06": test_attack_suite.test_t06_s3_metadata_injection,
                "T07": test_attack_suite.test_t07_security_group_injection,
            }
        except Exception:
            pass
    return _TEST_REGISTRY.get(test_id)


def evaluate_system_rule(rule: Rule) -> RuleEvaluationResult:
    """
    Evaluates an invariant system rule (e.g., R01-R07) by invoking its
    verifying test proof and asserting system boundaries.
    """
    test_callable = _get_test_callable(rule.test_id)
    if not test_callable:
        return RuleEvaluationResult(
            rule_id=rule.id,
            status="ERROR",
            test_id=rule.test_id,
            details=f"Verifying test '{rule.test_id}' not found in attack test registry.",
            severity=rule.severity.value,
            executed_proof=rule.proof,
            violations=[f"Unmapped test ID: {rule.test_id}"],
        )

    try:
        # Execute the formal attack / invariant test
        test_callable()
        return RuleEvaluationResult(
            rule_id=rule.id,
            status="PASS",
            test_id=rule.test_id,
            details=f"Rule verified via {rule.test_id}: {rule.description}",
            severity=rule.severity.value,
            executed_proof=f"Cryptographic/System Proof: {rule.proof}",
            violations=[],
        )
    except Exception as e:
        return RuleEvaluationResult(
            rule_id=rule.id,
            status="FAIL",
            test_id=rule.test_id,
            details=f"Rule violated during {rule.test_id}: {str(e)}",
            severity=rule.severity.value,
            executed_proof=f"Failed proof: {rule.proof}",
            violations=[str(e)],
        )


def evaluate_resource_rule(rule: Rule, evidence: Any) -> RuleEvaluationResult:
    """
    Evaluates a declarative resource compliance rule against an EvidenceRecord or dictionary.
    """
    # Check target resource type if specified
    if rule.target_resource_type:
        actual_type = None
        if hasattr(evidence, "resource_type"):
            actual_type = evidence.resource_type
        elif isinstance(evidence, dict):
            actual_type = evidence.get("resource_type")

        if actual_type and actual_type.lower() != rule.target_resource_type.lower():
            # Target does not apply to this evidence resource type
            return RuleEvaluationResult(
                rule_id=rule.id,
                status="SKIP",
                test_id=rule.test_id,
                details=f"Rule target '{rule.target_resource_type}' does not match evidence '{actual_type}'",
                severity=rule.severity.value,
                executed_proof="Type mismatch check",
                violations=[],
            )

    # Convert evidence to dict if it's an EvidenceRecord
    evidence_dict = evidence.to_dict() if hasattr(evidence, "to_dict") else evidence
    evidence_id = None
    if hasattr(evidence, "evidence_id"):
        evidence_id = evidence.evidence_id
    elif isinstance(evidence, dict):
        evidence_id = evidence.get("evidence_id")

    violations = []
    for cond in rule.conditions:
        exists, actual_val = resolve_field_path(evidence_dict, cond.field)
        passed = evaluate_operator(cond.operator, actual_val, cond.expected_value, exists=exists)
        if not passed:
            violations.append(
                f"Condition failed on field '{cond.field}': expected {cond.operator.value} "
                f"'{cond.expected_value}', but found '{actual_val}' (exists={exists})"
            )

    if not violations:
        return RuleEvaluationResult(
            rule_id=rule.id,
            status="PASS",
            test_id=rule.test_id,
            details=f"All {len(rule.conditions)} declarative conditions satisfied for {rule.id}",
            severity=rule.severity.value,
            executed_proof=rule.proof,
            violations=[],
            evidence_id=evidence_id,
        )
    else:
        return RuleEvaluationResult(
            rule_id=rule.id,
            status="FAIL",
            test_id=rule.test_id,
            details=f"Rule {rule.id} failed: {len(violations)} condition(s) unsatisfied.",
            severity=rule.severity.value,
            executed_proof=f"Violations detected against proof: {rule.proof}",
            violations=violations,
            evidence_id=evidence_id,
        )


def evaluate_rule(rule: Rule, evidence: Optional[Any] = None) -> RuleEvaluationResult:
    """Dispatches rule evaluation to the appropriate evaluator."""
    if rule.rule_type == RuleType.RESOURCE_COMPLIANCE:
        if evidence is None:
            return RuleEvaluationResult(
                rule_id=rule.id,
                status="ERROR",
                test_id=rule.test_id,
                details="Resource compliance rule requires an EvidenceRecord to evaluate.",
                severity=rule.severity.value,
                executed_proof=rule.proof,
                violations=["Missing evidence context"],
            )
        return evaluate_resource_rule(rule, evidence)
    else:
        return evaluate_system_rule(rule)
