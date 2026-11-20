from backend.audit import log_event
from backend.session_store import valid_session, SESSIONS


def approve(proposal, session_id):
    if not valid_session(session_id):
        raise PermissionError("Invalid session")

    if proposal.get("status") != "PENDING":
        raise ValueError("Invalid transition")

    old_status = proposal["status"]
    proposal["status"] = "APPROVED"

    approver = SESSIONS[session_id].get("username", "unknown")

    if "proposal_id" in proposal:
        try:
            from backend.database import get_connection
            conn = get_connection()
            conn.execute(
                "UPDATE proposals SET status = ? WHERE proposal_id = ?",
                ("APPROVED", proposal["proposal_id"])
            )
            conn.commit()
            conn.close()
        except Exception:
            pass

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
        try:
            from backend.database import get_connection
            conn = get_connection()
            conn.execute(
                "UPDATE proposals SET status = ? WHERE proposal_id = ?",
                ("REJECTED", proposal["proposal_id"])
            )
            conn.commit()
            conn.close()
        except Exception:
            pass

    log_event(
        "proposal_rejected",
        {
            "approver": approver,
            "old": old_status,
            "new": "REJECTED"
        }
    )

    return proposal
