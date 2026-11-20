import json
import pytest
from backend.audit import log_event, verify_audit_hash_chain, verify_zero_mutations
from backend.auth import verify_password
from backend.session_store import create_session, valid_session, get_session, destroy_session
from backend.proposals import create_proposal
from backend.approvals import approve_by_id, reject_by_id


def test_auth_and_session_lifecycle():
    import os
    import bcrypt

    # Without hash configured, authentication is strictly denied
    if "APPROVER_PASSWORD_HASH" in os.environ:
        del os.environ["APPROVER_PASSWORD_HASH"]
    assert verify_password("AnyPassword") is False

    # With valid hash configured
    test_pwd = "TestSecurePassword123!"
    os.environ["APPROVER_PASSWORD_HASH"] = bcrypt.hashpw(test_pwd.encode(), bcrypt.gensalt()).decode()
    try:
        assert verify_password(test_pwd) is True
        assert verify_password("WrongPassword123") is False
    finally:
        del os.environ["APPROVER_PASSWORD_HASH"]

    session_id = create_session("admin")
    assert valid_session(session_id) is True

    session_data = get_session(session_id)
    assert session_data["username"] == "admin"
    assert "csrf_token" in session_data

    assert destroy_session(session_id) is True
    assert valid_session(session_id) is False


def test_audit_hash_chain_integrity():
    event1 = log_event("chain_test_event_1", {"key": "val1"})
    assert "prev_hash" in event1
    assert "event_hash" in event1

    event2 = log_event("chain_test_event_2", {"key": "val2"})
    assert event2["prev_hash"] == event1["event_hash"]

    assert verify_audit_hash_chain() is True
    assert verify_zero_mutations() is True


def test_approval_by_id_lifecycle():
    proposal = create_proposal("F-S3-001", "bucket-test-001", "Block Public Access")
    pid = proposal["proposal_id"]

    # Reject unauthenticated approval
    with pytest.raises(PermissionError):
        approve_by_id(pid, "unauthenticated_session")

    # Approve with valid session
    session_id = create_session("sec_officer")
    res = approve_by_id(pid, session_id)
    assert res["status"] == "APPROVED"
    assert res["approver"] == "sec_officer"

    # Reject invalid transition
    with pytest.raises(ValueError, match="Invalid transition"):
        approve_by_id(pid, session_id)


def test_agentcore_client_status():
    from agent.agentcore_client import AgentCoreClient
    client = AgentCoreClient()
    status = client.get_status()
    assert "configured_region" in status
    assert "harness_arn" in status
    assert "aws_credentials_present" in status


def test_api_new_endpoints_integration(tmp_path):
    from backend.observability.health import check_system_health
    from backend.observability.metrics import collect_system_metrics
    from backend.intelligence.service import MultiSourceIntelligenceService
    from backend.graph.engine import ResourceGraph
    from backend.graph.visualizer import GraphVisualizer
    from backend.compliance.service import ComplianceService
    from backend.governance.proof_chain import ProofChainService

    db_file = str(tmp_path / "api_test.db")

    # Health & Metrics
    health = check_system_health(db_path=db_file)
    assert health["status"] in ("healthy", "degraded")
    metrics = collect_system_metrics(db_path=db_file)
    assert "security_metrics" in metrics

    # Intelligence & Inventory
    intel_svc = MultiSourceIntelligenceService(db_path=db_file)
    findings = intel_svc.ingest_all_sources()
    assert len(findings) >= 5
    assets = intel_svc.inventory.list_assets()
    assert len(assets) >= 2

    # Graph & Topology
    graph = ResourceGraph.build_default_topology()
    cytoscape_elements = GraphVisualizer.to_cytoscape_elements(graph)
    assert len(cytoscape_elements) >= 10

    # Compliance
    comp_report = ComplianceService.evaluate_compliance(findings=findings)
    assert "CIS-AWS-v3.0" in comp_report
    assert "NIST-CSF-2.0" in comp_report

    # Proof Chain
    pc_svc = ProofChainService(db_path=db_file)
    chain = pc_svc.create_investigation_chain(
        finding_id=findings[0].finding_id,
        resource_arn=findings[0].resource_arn,
        evidence_id="EV-TEST",
        evidence_digest="hash_test",
        rule_id="SEC-S3-001",
        rule_version="1.0.0",
        rule_set_digest="rules_hash",
        risk_score=90.0,
        risk_policy_version="2.0.0",
        remediation_action="enable_s3_block_public_access",
        parameters={"bucket_name": "test-bucket"}
    )
    assert chain.lifecycle_state.value == "PENDING"
    chains = pc_svc.list_chains()
    assert len(chains) == 1
