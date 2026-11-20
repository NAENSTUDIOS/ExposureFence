def approve(proposal):
    if proposal["status"] != "PENDING":
        raise ValueError("Invalid transition")

    proposal["status"] = "APPROVED"

    return proposal


def reject(proposal):
    if proposal["status"] != "PENDING":
        raise ValueError("Invalid transition")

    proposal["status"] = "REJECTED"

    return proposal