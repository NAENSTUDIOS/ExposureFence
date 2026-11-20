from backend.database import initialize_db
from backend.proposals import create_proposal


def test_create_proposal():

    initialize_db()

    proposal = create_proposal(
        "F-001",
        "bucket-public-001",
        "Disable public access"
    )

    assert proposal["status"] == "PENDING"