import uuid

from backend.database import get_connection


def create_proposal(
    finding_id,
    resource_id,
    remediation
):
    proposal_id = str(uuid.uuid4())

    conn = get_connection()

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

    conn.commit()
    conn.close()

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