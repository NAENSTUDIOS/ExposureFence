"""
ExposureFence — Phase 5 Declarative Rules Engine Tests
Comprehensive unit and integration test suite verifying safe YAML parsing,
schema validation, deterministic condition operators, system invariant execution,
evidence-driven compliance, and audit trail linkage.
"""

import os
import pytest

from backend.rules.evaluator import evaluate_resource_rule, evaluate_system_rule
from backend.rules.exceptions import (
    RuleEvaluationError,
    RuleSchemaError,
    RuleSyntaxError,
    UntrustedRuleContentError,
)
from backend.rules.models import (
    OperatorType,
    Rule,
    RuleCondition,
    RuleSeverity,
    RuleType,
)
from backend.rules.operators import (
    evaluate_operator,
    resolve_field_path,
)
from backend.rules.parser import (
    SafeYAMLParser,
    load_rules_from_yaml,
    safe_load_yaml,
)
from backend.rules.schema import validate_rule, validate_rules_collection
from backend.rules.service import RulesEngine


# ==============================================================================
# 1. Safe YAML Parser Tests
# ==============================================================================

def test_safe_yaml_parser_mappings_and_lists():
    yaml_text = """
    app: ExposureFence
    version: 1.0.0
    enabled: true
    ports:
      - 22
      - 80
      - 443
    metadata:
      environment: dev
      owner: SecOps
    """
    res = safe_load_yaml(yaml_text)
    assert res["app"] == "ExposureFence"
    assert res["version"] == "1.0.0"
    assert res["enabled"] is True
    assert res["ports"] == [22, 80, 443]
    assert res["metadata"]["environment"] == "dev"
    assert res["metadata"]["owner"] == "SecOps"


def test_safe_yaml_parser_scalars_and_quotes():
    yaml_text = """
    int_val: 42
    float_val: 3.14
    str_unquoted: hello world
    str_double_quoted: "hello \\"world\\""
    str_single_quoted: 'hello world'
    bool_true: true
    bool_false: false
    null_val: null
    """
    res = safe_load_yaml(yaml_text)
    assert res["int_val"] == 42
    assert res["float_val"] == 3.14
    assert res["str_unquoted"] == "hello world"
    assert res["str_double_quoted"] == 'hello "world"'
    assert res["str_single_quoted"] == "hello world"
    assert res["bool_true"] is True
    assert res["bool_false"] is False
    assert res["null_val"] is None


def test_safe_yaml_parser_comments_and_whitespace():
    yaml_text = """
    # File header comment
    rule:
      id: R01 # Inline comment
      # Middle comment
      test_id: T01
    """
    res = safe_load_yaml(yaml_text)
    assert res["rule"]["id"] == "R01"
    assert res["rule"]["test_id"] == "T01"


def test_safe_yaml_parser_rejects_untrusted_tags():
    yaml_text = """
    rule:
      id: MALICIOUS
      action: !python/object/apply:os.system ["calc.exe"]
    """
    with pytest.raises(UntrustedRuleContentError) as exc_info:
        safe_load_yaml(yaml_text)
    assert "Untrusted YAML tag detected" in str(exc_info.value)


# ==============================================================================
# 2. Schema Validation Tests
# ==============================================================================

def test_rule_schema_validation_success():
    rule = Rule(
        id="R01",
        description="Mock data only",
        allowed_action="Read mock fixtures",
        forbidden_action="Read AWS resources",
        enforcement_layer="Application Boundary",
        test_id="T01",
        proof="Fixture hash validation",
        severity=RuleSeverity.CRITICAL,
        rule_type=RuleType.INVARIANT_TEST,
    )
    validate_rule(rule)  # Should not raise


def test_rule_schema_validation_missing_fields():
    rule = Rule(
        id="",
        description="Missing id",
        allowed_action="Read mock fixtures",
        forbidden_action="Read AWS resources",
        enforcement_layer="Application Boundary",
        test_id="T01",
        proof="Fixture hash validation",
    )
    with pytest.raises(RuleSchemaError):
        validate_rule(rule)


def test_rule_schema_validation_duplicate_ids():
    rule1 = Rule(
        id="R01",
        description="Mock data only",
        allowed_action="Read mock fixtures",
        forbidden_action="Read AWS resources",
        enforcement_layer="Application Boundary",
        test_id="T01",
        proof="Fixture hash validation",
    )
    rule2 = Rule(
        id="R01",
        description="Duplicate rule",
        allowed_action="Read mock fixtures",
        forbidden_action="Read AWS resources",
        enforcement_layer="Application Boundary",
        test_id="T01",
        proof="Fixture hash validation",
    )
    with pytest.raises(RuleSchemaError) as exc_info:
        validate_rules_collection([rule1, rule2])
    assert "Duplicate rule ID" in str(exc_info.value)


# ==============================================================================
# 3. Deterministic Operators Tests
# ==============================================================================

def test_resolve_field_path():
    data = {
        "payload": {
            "public_access_block": {
                "BlockPublicAcls": True
            },
            "tags": ["prod", "pci"]
        }
    }
    exists, val = resolve_field_path(data, "payload.public_access_block.BlockPublicAcls")
    assert exists is True
    assert val is True

    exists, val = resolve_field_path(data, "payload.tags[1]")
    assert exists is True
    assert val == "pci"

    exists, val = resolve_field_path(data, "payload.nonexistent.field")
    assert exists is False
    assert val is None


def test_operator_equals_and_not_equals():
    assert evaluate_operator(OperatorType.EQUALS, 42, 42) is True
    assert evaluate_operator(OperatorType.EQUALS, "open", "closed") is False
    assert evaluate_operator(OperatorType.NOT_EQUALS, "restricted", "public") is True


def test_operator_contains_and_in_list():
    assert evaluate_operator(OperatorType.CONTAINS, ["admin", "secops"], "admin") is True
    assert evaluate_operator(OperatorType.NOT_CONTAINS, ["guest"], "admin") is True
    assert evaluate_operator(OperatorType.IN_LIST, "s3", ["s3", "ec2", "iam"]) is True
    assert evaluate_operator(OperatorType.NOT_IN_LIST, "rds", ["s3", "ec2", "iam"]) is True


def test_operator_cidr_in():
    assert evaluate_operator(OperatorType.CIDR_IN, "10.0.1.5", "10.0.0.0/16") is True
    assert evaluate_operator(OperatorType.CIDR_IN, "10.0.1.0/24", "10.0.0.0/16") is True
    assert evaluate_operator(OperatorType.CIDR_IN, "192.168.1.1", "10.0.0.0/16") is False


def test_operator_port_in():
    assert evaluate_operator(OperatorType.PORT_IN, 22, 22) is True
    assert evaluate_operator(OperatorType.PORT_IN, 22, "20-25") is True
    assert evaluate_operator(OperatorType.PORT_IN, 80, [20, 25]) is False


def test_operator_not_contains_open_port():
    # Dangerous: 0.0.0.0/0 on port 22
    open_perms = [
        {
            "FromPort": 22,
            "ToPort": 22,
            "IpProtocol": "tcp",
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
        }
    ]
    # Should return False (violation detected!)
    assert evaluate_operator(OperatorType.NOT_CONTAINS_OPEN_PORT, open_perms, 22) is False

    # Safe: restricted CIDR 10.0.0.0/16 on port 22
    safe_perms = [
        {
            "FromPort": 22,
            "ToPort": 22,
            "IpProtocol": "tcp",
            "IpRanges": [{"CidrIp": "10.0.0.0/16"}]
        }
    ]
    assert evaluate_operator(OperatorType.NOT_CONTAINS_OPEN_PORT, safe_perms, 22) is True

    # Safe: 0.0.0.0/0 on port 443 (HTTPS), port 22 is NOT exposed
    https_perms = [
        {
            "FromPort": 443,
            "ToPort": 443,
            "IpProtocol": "tcp",
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
        }
    ]
    assert evaluate_operator(OperatorType.NOT_CONTAINS_OPEN_PORT, https_perms, 22) is True


def test_operator_field_exists_and_missing():
    assert evaluate_operator(OperatorType.FIELD_EXISTS, "val", None, exists=True) is True
    assert evaluate_operator(OperatorType.FIELD_MISSING, None, None, exists=False) is True


def test_operator_regex_match():
    assert evaluate_operator(OperatorType.REGEX_MATCH, "arn:aws:s3:::my-bucket", r"^arn:aws:s3:::") is True
    assert evaluate_operator(OperatorType.REGEX_MATCH, "invalid-arn", r"^arn:aws:s3:::") is False


# ==============================================================================
# 4. Rule Evaluation Tests (System & Resource)
# ==============================================================================

def test_system_rules_r01_to_r07_evaluation_pass():
    engine = RulesEngine()
    for rule_id in ["R01", "R02", "R03", "R04", "R05", "R06", "R07"]:
        res = engine.evaluate_rule(rule_id)
        assert res.status == "PASS", f"Rule {rule_id} failed: {res.violations}"
        assert res.rule_id == rule_id
        assert len(res.violations) == 0


def test_resource_compliance_rule_s3_pass_and_fail():
    rule = Rule(
        id="SEC-S3-TEST",
        description="S3 bucket must not have public exposure",
        allowed_action="Read bucket",
        forbidden_action="Public access",
        enforcement_layer="Cloud Resource",
        test_id="T_S3",
        proof="Access block",
        severity=RuleSeverity.HIGH,
        rule_type=RuleType.RESOURCE_COMPLIANCE,
        target_resource_type="AWS::S3::Bucket",
        conditions=[
            RuleCondition(
                field="payload.normalized_evidence.is_public",
                operator=OperatorType.EQUALS,
                expected_value=False
            )
        ]
    )

    # Compliant evidence
    private_ev = {
        "evidence_id": "EV-TEST-PRIVATE",
        "resource_type": "AWS::S3::Bucket",
        "payload": {
            "normalized_evidence": {
                "is_public": False
            }
        }
    }
    res_pass = evaluate_resource_rule(rule, private_ev)
    assert res_pass.status == "PASS"

    # Non-compliant evidence (public exposure)
    public_ev = {
        "evidence_id": "EV-TEST-PUBLIC",
        "resource_type": "AWS::S3::Bucket",
        "payload": {
            "normalized_evidence": {
                "is_public": True
            }
        }
    }
    res_fail = evaluate_resource_rule(rule, public_ev)
    assert res_fail.status == "FAIL"
    assert len(res_fail.violations) > 0


def test_resource_compliance_rule_sg_ssh_pass_and_fail():
    rule = Rule(
        id="SEC-SG-TEST",
        description="SG must not expose SSH to internet",
        allowed_action="Restrict SSH",
        forbidden_action="Public SSH",
        enforcement_layer="Cloud Resource",
        test_id="T_SG",
        proof="Permissions check",
        severity=RuleSeverity.CRITICAL,
        rule_type=RuleType.RESOURCE_COMPLIANCE,
        target_resource_type="AWS::EC2::SecurityGroup",
        conditions=[
            RuleCondition(
                field="payload.normalized_evidence.is_public",
                operator=OperatorType.EQUALS,
                expected_value=False
            )
        ]
    )

    safe_sg = {
        "evidence_id": "EV-SG-SAFE",
        "resource_type": "AWS::EC2::SecurityGroup",
        "payload": {
            "normalized_evidence": {
                "is_public": False
            }
        }
    }
    assert evaluate_resource_rule(rule, safe_sg).status == "PASS"

    open_sg = {
        "evidence_id": "EV-SG-OPEN",
        "resource_type": "AWS::EC2::SecurityGroup",
        "payload": {
            "normalized_evidence": {
                "is_public": True
            }
        }
    }
    assert evaluate_resource_rule(rule, open_sg).status == "FAIL"


# ==============================================================================
# 5. Service & Ledger Integration Tests
# ==============================================================================

def test_rules_engine_evaluate_all():
    engine = RulesEngine()
    result = engine.evaluate_all(run_full_pytest=False)

    assert result["score_pct"] == 100
    assert result["all_passed"] is True
    assert result["passed_rules"] == 7
    for rid in ["R01", "R02", "R03", "R04", "R05", "R06", "R07"]:
        assert result["rule_results"][rid] == "PASS"
    for tid in ["T01", "T02", "T03", "T04", "T05", "T06", "T07"]:
        assert result["attack_results"][tid] == "PASS"


def test_rules_engine_evidence_relationship_recording():
    from backend.evidence.collector import collect_all_mock_evidence
    from backend.evidence.repository import EvidenceRepository, initialize_evidence_tables

    initialize_evidence_tables()
    engine = RulesEngine()
    repo = EvidenceRepository()

    mock_records = collect_all_mock_evidence()
    assert len(mock_records) >= 4

    # Ensure evidence record is stored in repo before testing relationships
    test_record = mock_records[0]
    try:
        repo.store_evidence_record(test_record)
    except Exception:
        pass

    eval_results = engine.evaluate_evidence(test_record, record_relationship=True)

    if eval_results:
        rels = repo.get_relationships_for_evidence(test_record.evidence_id)
        assert len(rels) >= 1
        rule_rel = next((r for r in rels if r.entity_id.startswith("rule:")), None)
        assert rule_rel is not None
        assert rule_rel.relationship_type == "DERIVED_FROM"


def test_rules_engine_audit_event_emission():
    from backend.audit import get_audit_events

    engine = RulesEngine()
    engine.evaluate_rule("R01")

    events = get_audit_events()
    eval_events = [e for e in events if e.get("event_type") == "RULE_EVALUATION"]
    assert len(eval_events) > 0
    latest = eval_events[-1]
    assert latest["details"]["rule_id"] == "R01"
    assert latest["details"]["status"] == "PASS"


def test_api_rules_endpoints():
    import json
    from io import BytesIO
    from backend.server import ExposureFenceHandler

    class DummyServer:
        pass

    class MockHandler(ExposureFenceHandler):
        def __init__(self, path, method="GET", body=b""):
            self.path = path
            self.command = method
            self.request_version = "HTTP/1.1"
            self.headers = {"Content-Length": str(len(body))}
            self.rfile = BytesIO(body)
            self.wfile = BytesIO()
            self.server = DummyServer()

        def send_response(self, code, message=None):
            self.response_code = code

        def send_header(self, keyword, value):
            pass

        def end_headers(self):
            pass

    # 1. Test GET /api/rules
    h_get = MockHandler("/api/rules", "GET")
    h_get.do_GET()
    output = json.loads(h_get.wfile.getvalue().decode("utf-8"))
    assert isinstance(output, list)
    assert len(output) >= 7
    assert any(r["id"] == "R01" for r in output)

    # 2. Test GET /api/rules/evaluate
    h_eval = MockHandler("/api/rules/evaluate", "GET")
    h_eval.do_GET()
    eval_out = json.loads(h_eval.wfile.getvalue().decode("utf-8"))
    assert eval_out["score_pct"] == 100
    assert eval_out["all_passed"] is True

