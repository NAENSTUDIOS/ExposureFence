from backend.audit import log_event
from backend.session_store import valid_session, SESSIONS
from backend.database import get_connection


def approve(proposal, session_id):
    if not valid_session(session_id):
        raise PermissionError("Invalid session")

    if proposal.get("status") != "PENDING":
        raise ValueError("Invalid transition")

    # Stale evidence and tampering verification
    proposal_id = proposal.get("proposal_id")
    if proposal_id:
        from backend.evidence.relationships import verify_proposal_evidence_binding
        can_proceed, reason, evidence = verify_proposal_evidence_binding(proposal_id)
        if not can_proceed:
            raise PermissionError(f"Approval blocked by Evidence Governance: {reason}")

    old_status = proposal["status"]
    proposal["status"] = "APPROVED"

    approver = SESSIONS[session_id].get("username", "unknown")

    if "proposal_id" in proposal:
        conn = get_connection()
        try:
            with conn:
                conn.execute(
                    "UPDATE proposals SET status = ? WHERE proposal_id = ?",
                    ("APPROVED", proposal["proposal_id"])
                )
        finally:
            conn.close()

    log_event(
        "proposal_approved",
        {
            "approver": approver,
            "old": old_status,
            "new": "APPROVED"
        }
    )

    return proposal


def reject(proposal, session_id):
    if not valid_session(session_id):
        raise PermissionError("Invalid session")

    if proposal.get("status") != "PENDING":
        raise ValueError("Invalid transition")

    old_status = proposal["status"]
    proposal["status"] = "REJECTED"

    approver = SESSIONS[session_id].get("username", "unknown")

    if "proposal_id" in proposal:
        conn = get_connection()
        try:
            with conn:
                conn.execute(
                    "UPDATE proposals SET status = ? WHERE proposal_id = ?",
                    ("REJECTED", proposal["proposal_id"])
                )
        finally:
            conn.close()

    log_event(
        "proposal_rejected",
        {
            "approver": approver,
            "old": old_status,
            "new": "REJECTED"
        }
    )

    return proposal


def approve_by_id(proposal_id: str, session_id: str):
    if not valid_session(session_id):
        raise PermissionError("Invalid session")

    # Stale evidence and tampering verification
    from backend.evidence.relationships import verify_proposal_evidence_binding
    can_proceed, reason, evidence = verify_proposal_evidence_binding(proposal_id)
    if not can_proceed:
        raise PermissionError(f"Approval blocked by Evidence Governance: {reason}")

    conn = get_connection()
    try:
        with conn:
            row = conn.execute(
                "SELECT proposal_id, finding_id, resource_id, remediation, status FROM proposals WHERE proposal_id = ?",
                (proposal_id,)
            ).fetchone()

            if not row:
                raise ValueError(f"Proposal {proposal_id} not found")

            if row[4] != "PENDING":
                raise ValueError("Invalid transition")

            conn.execute("UPDATE proposals SET status = 'APPROVED' WHERE proposal_id = ?", (proposal_id,))
    finally:
        conn.close()

    approver = SESSIONS[session_id].get("username", "unknown")
    log_event(
        "proposal_approved",
        {
            "proposal_id": proposal_id,
            "approver": approver,
            "old": "PENDING",
            "new": "APPROVED"
        }
    )

    return {
        "proposal_id": proposal_id,
        "finding_id": row[1],
        "resource_id": row[2],
        "remediation": row[3],
        "status": "APPROVED",
        "approver": approver
    }


def reject_by_id(proposal_id: str, session_id: str):
    if not valid_session(session_id):
        raise PermissionError("Invalid session")

    conn = get_connection()
    try:
        with conn:
            row = conn.execute(
                "SELECT proposal_id, finding_id, resource_id, remediation, status FROM proposals WHERE proposal_id = ?",
                (proposal_id,)
            ).fetchone()

            if not row:
                raise ValueError(f"Proposal {proposal_id} not found")

            if row[4] != "PENDING":
                raise ValueError("Invalid transition")

            conn.execute("UPDATE proposals SET status = 'REJECTED' WHERE proposal_id = ?", (proposal_id,))
    finally:
        conn.close()

    approver = SESSIONS[session_id].get("username", "unknown")
    log_event(
        "proposal_rejected",
        {
            "proposal_id": proposal_id,
            "approver": approver,
            "old": "PENDING",
            "new": "REJECTED"
        }
    )

    return {
        "proposal_id": proposal_id,
        "finding_id": row[1],
        "resource_id": row[2],
        "remediation": row[3],
        "status": "REJECTED",
        "approver": approver
    }
