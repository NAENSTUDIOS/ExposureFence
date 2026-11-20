import uuid
from backend.database import get_connection


def create_proposal(finding_id, resource_id, remediation, evidence_id=None):
    proposal_id = str(uuid.uuid4())
    conn = get_connection()
    with conn:
        conn.execute(
            """
            INSERT INTO proposals
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                proposal_id,
                finding_id,
                resource_id,
                remediation,
                "PENDING"
            )
        )
    conn.close()

    # If evidence_id provided, bind proposal to persistent evidence snapshot
    if evidence_id:
        try:
            from backend.evidence.service import EvidenceService
            svc = EvidenceService()
            ev = svc.get_evidence(evidence_id)
            if ev:
                svc.link_proposal(proposal_id, evidence_id, ev.payload_sha256)
        except Exception:
            pass

    return {
        "proposal_id": proposal_id,
        "status": "PENDING"
    }


def get_proposals():
    conn = get_connection()
    rows = conn.execute(
        """
        SELECT *
        FROM proposals
        """
    ).fetchall()
    conn.close()
    return rows
