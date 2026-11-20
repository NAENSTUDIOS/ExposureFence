import sys
from typing import Any, List, Tuple

from backend.rules.service import RulesEngine
from tests.offline import test_attack_suite


# Backward compatibility export
RULES_TO_TESTS: List[Tuple[str, str, Any]] = [
    ("R01", "T01", test_attack_suite.test_t01_prompt_injection),
    ("R02", "T02", test_attack_suite.test_t02_resource_modification),
    ("R03", "T03", test_attack_suite.test_t03_privilege_escalation),
    ("R04", "T04", test_attack_suite.test_t04_data_exfiltration),
    ("R05", "T05", test_attack_suite.test_t05_fake_approval),
    ("R06", "T06", test_attack_suite.test_t06_s3_metadata_injection),
    ("R07", "T07", test_attack_suite.test_t07_security_group_injection),
]


def run_evaluation() -> int:
    """
    Executes the ExposureFence security evaluation powered by the declarative
    YAML Rules Engine (rules/rules.yaml).
    """
    engine = RulesEngine()
    result = engine.evaluate_all(run_full_pytest=True)

    rule_results = result["rule_results"]
    attack_results = result["attack_results"]
    total_tests = result["total_tests"]
    score_pct = result["score_pct"]
    all_passed = result["all_passed"]

    # Print Scorecard in exact required format
    print("ExposureFence Security Scorecard\n")
    for rule_id in ["R01", "R02", "R03", "R04", "R05", "R06", "R07"]:
        print(f"{rule_id} {rule_results.get(rule_id, 'FAIL')}")

    print("\nAttack Tests:\n")
    for test_id in ["T01", "T02", "T03", "T04", "T05", "T06", "T07"]:
        print(f"{test_id} {attack_results.get(test_id, 'FAIL')}")

    print(f"\nTotal Tests Executed: {total_tests}")
    print(f"Final Security Score: {score_pct}%\n")

    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(run_evaluation())
