import contextlib
import io
import sys
import pytest

from tests.offline import test_attack_suite


RULES_TO_TESTS = [
    ("R01", "T01", test_attack_suite.test_t01_prompt_injection),
    ("R02", "T02", test_attack_suite.test_t02_resource_modification),
    ("R03", "T03", test_attack_suite.test_t03_privilege_escalation),
    ("R04", "T04", test_attack_suite.test_t04_data_exfiltration),
    ("R05", "T05", test_attack_suite.test_t05_fake_approval),
    ("R06", "T06", test_attack_suite.test_t06_s3_metadata_injection),
    ("R07", "T07", test_attack_suite.test_t07_security_group_injection),
]


class _PytestCapture:
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


def run_evaluation():
    # 1. Execute individual attack tests and rules
    rule_results = {}
    attack_results = {}

    for rule_id, test_id, test_fn in RULES_TO_TESTS:
        try:
            test_fn()
            rule_results[rule_id] = "PASS"
            attack_results[test_id] = "PASS"
        except Exception as e:
            rule_results[rule_id] = f"FAIL ({e})"
            attack_results[test_id] = f"FAIL ({e})"

    # 2. Run full pytest suite quietly to get total tests executed
    capture = _PytestCapture()
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        pytest.main(["tests/offline", "backend/test_database.py"], plugins=[capture])

    total_tests = capture.total if capture.total > 0 else len(RULES_TO_TESTS)

    # 3. Calculate final score
    passed_rules = sum(1 for status in rule_results.values() if status == "PASS")
    total_rules = len(RULES_TO_TESTS)
    score_pct = int((passed_rules / total_rules) * 100)

    # 4. Print Scorecard in exact required format
    print("ExposureFence Security Scorecard\n")
    for rule_id in ["R01", "R02", "R03", "R04", "R05", "R06", "R07"]:
        print(f"{rule_id} {rule_results.get(rule_id, 'FAIL')}")

    print("\nAttack Tests:\n")
    for test_id in ["T01", "T02", "T03", "T04", "T05", "T06", "T07"]:
        print(f"{test_id} {attack_results.get(test_id, 'FAIL')}")

    print(f"\nTotal Tests Executed: {total_tests}")
    print(f"Final Security Score: {score_pct}%\n")

    return 0 if passed_rules == total_rules else 1


if __name__ == "__main__":
    sys.exit(run_evaluation())
