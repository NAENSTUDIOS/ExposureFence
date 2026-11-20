"""
ExposureFence — Rules Engine Service
Orchestrates declarative rule loading, validation, evaluation, evidence binding,
and audit trail integration.
"""

import contextlib
import io
import os
from typing import Any, Dict, List, Optional

from backend.rules.evaluator import evaluate_rule
from backend.rules.exceptions import RuleEvaluationError, RuleSchemaError
from backend.rules.models import Rule, RuleEvaluationResult, RuleType
from backend.rules.parser import load_rules_from_yaml
from backend.rules.schema import validate_rules_collection


DEFAULT_RULES_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "rules", "rules.yaml"
)


class _PytestCounter:
    def __init__(self):
        self.total = 0
        self.passed = 0
        self.failed = 0

    def pytest_runtest_logreport(self, report):
        if report.when == "call":
            self.total += 1
            if report.passed:
                self.passed += 1
            elif report.failed:
                self.failed += 1


class RulesEngine:
    """
    Central service for the ExposureFence YAML-driven security rules engine.
    """

    def __init__(self, rules_path: Optional[str] = None):
        self.rules_path = rules_path or DEFAULT_RULES_PATH
        self._rules: Dict[str, Rule] = {}
        self.reload_rules()

    def reload_rules(self) -> None:
        """Loads and validates all rules from the YAML specification."""
        if not os.path.exists(self.rules_path):
            raise FileNotFoundError(f"Rules configuration file not found at: {self.rules_path}")

        loaded_rules = load_rules_from_yaml(self.rules_path)
        validate_rules_collection(loaded_rules)
        self._rules = {rule.id: rule for rule in loaded_rules}

    def list_rules(self) -> List[Rule]:
        """Returns a list of all loaded rules."""
        return list(self._rules.values())

    def get_rule(self, rule_id: str) -> Optional[Rule]:
        """Retrieves a rule by its ID."""
        return self._rules.get(rule_id)

    def evaluate_rule(self, rule_id: str, evidence: Optional[Any] = None) -> RuleEvaluationResult:
        """Evaluates a single rule by ID."""
        rule = self.get_rule(rule_id)
        if not rule:
            raise RuleEvaluationError(f"Rule with ID '{rule_id}' not found in active ruleset.")

        result = evaluate_rule(rule, evidence=evidence)

        # Log rule evaluation in audit trail
        try:
            from backend.audit import log_event
            log_event(
                "RULE_EVALUATION",
                {
                    "rule_id": result.rule_id,
                    "test_id": result.test_id,
                    "status": result.status,
                    "evidence_id": result.evidence_id,
                    "violations_count": len(result.violations),
                },
            )
        except Exception:
            pass

        return result

    def evaluate_evidence(
        self, evidence: Any, record_relationship: bool = True
    ) -> List[RuleEvaluationResult]:
        """
        Evaluates all applicable resource compliance rules against an EvidenceRecord.
        If record_relationship is True, stores a relationship in the evidence ledger.
        """
        results = []
        for rule in self._rules.values():
            if rule.rule_type == RuleType.RESOURCE_COMPLIANCE:
                res = self.evaluate_rule(rule.id, evidence=evidence)
                if res.status != "SKIP":
                    results.append(res)

                    # Store relationship in evidence repository if enabled
                    if record_relationship and res.evidence_id:
                        try:
                            from backend.evidence.relationships import bind_evidence_to_entity
                            from backend.evidence.models import EntityType, RelationshipType

                            payload_sha = getattr(evidence, "payload_sha256", "")
                            bind_evidence_to_entity(
                                evidence_id=res.evidence_id,
                                entity_type=EntityType.PROPOSAL.value,
                                entity_id=f"rule:{rule.id}",
                                bound_payload_sha256=payload_sha,
                                relationship_type=RelationshipType.DERIVED_FROM.value,
                            )
                        except Exception:
                            pass
        return results

    def evaluate_all(self, run_full_pytest: bool = True) -> Dict[str, Any]:
        """
        Evaluates all active rules and produces a comprehensive security scorecard.
        System invariant rules (R01-R07) are evaluated against their formal attack tests.
        Resource compliance rules are evaluated against available evidence records.
        """
        rule_results: Dict[str, str] = {}
        attack_results: Dict[str, str] = {}
        detailed_results: List[Dict[str, Any]] = []

        system_rules = [
            r for r in self._rules.values() if r.rule_type == RuleType.INVARIANT_TEST
        ]

        # 1. Evaluate system invariant rules
        for rule in system_rules:
            res = self.evaluate_rule(rule.id)
            rule_results[rule.id] = res.status
            attack_results[rule.test_id] = res.status
            detailed_results.append(res.to_dict())

        # 2. Evaluate resource compliance rules if mock fixtures exist
        resource_rules = [
            r for r in self._rules.values() if r.rule_type == RuleType.RESOURCE_COMPLIANCE
        ]
        resource_evaluations: List[Dict[str, Any]] = []

        if resource_rules:
            try:
                from backend.evidence.collector import collect_all_mock_evidence
                mock_evidence = collect_all_mock_evidence()
                for ev in mock_evidence:
                    ev_results = self.evaluate_evidence(ev, record_relationship=False)
                    for r_res in ev_results:
                        resource_evaluations.append(r_res.to_dict())
            except Exception:
                pass

        # 3. Calculate system scorecard metrics
        passed_rules = sum(1 for status in rule_results.values() if status == "PASS")
        total_rules = len(system_rules)
        score_pct = int((passed_rules / total_rules) * 100) if total_rules > 0 else 100

        total_tests = total_rules
        if run_full_pytest:
            try:
                import pytest
                counter = _PytestCounter()
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    pytest.main(["tests/offline", "backend/test_database.py"], plugins=[counter])
                if counter.total > 0:
                    total_tests = counter.total
            except Exception:
                pass

        return {
            "rule_results": rule_results,
            "attack_results": attack_results,
            "detailed_results": detailed_results,
            "resource_evaluations": resource_evaluations,
            "passed_rules": passed_rules,
            "total_rules": total_rules,
            "total_tests": total_tests,
            "score_pct": score_pct,
            "all_passed": passed_rules == total_rules,
        }
