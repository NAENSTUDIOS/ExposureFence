"""
ExposureFence — Role-Based Access Control (RBAC) Package
Enforces least-privilege role boundaries: INVESTIGATOR, APPROVER, AUDITOR, ADMINISTRATOR.
"""

from enum import Enum
from typing import Dict, List, Set


class Role(str, Enum):
    INVESTIGATOR = "INVESTIGATOR"
    APPROVER = "APPROVER"
    AUDITOR = "AUDITOR"
    ADMINISTRATOR = "ADMINISTRATOR"


# Action permissions matrix
ROLE_PERMISSIONS: Dict[Role, Set[str]] = {
    Role.INVESTIGATOR: {
        "read:findings",
        "read:graph",
        "read:risk",
        "read:evidence",
        "invoke:agent",
        "create:proposal",
        "read:proposals",
        "read:compliance"
    },
    Role.APPROVER: {
        "read:findings",
        "read:graph",
        "read:risk",
        "read:evidence",
        "invoke:agent",
        "create:proposal",
        "read:proposals",
        "approve:proposal",
        "reject:proposal",
        "create:risk_acceptance",
        "read:compliance"
    },
    Role.AUDITOR: {
        "read:findings",
        "read:graph",
        "read:risk",
        "read:evidence",
        "read:proposals",
        "read:audit",
        "verify:audit_chain",
        "read:compliance",
        "read:dossier"
    },
    Role.ADMINISTRATOR: {
        "read:findings",
        "read:graph",
        "read:risk",
        "read:evidence",
        "invoke:agent",
        "create:proposal",
        "read:proposals",
        "approve:proposal",
        "reject:proposal",
        "create:risk_acceptance",
        "revoke:risk_acceptance",
        "execute:remediation",
        "read:audit",
        "verify:audit_chain",
        "read:compliance",
        "read:dossier",
        "manage:users",
        "admin:system"
    }
}


class RBACService:
    """Evaluates role-based permissions against attempted operations."""

    @staticmethod
    def has_permission(role: str, action: str) -> bool:
        try:
            r = Role(role.upper())
            allowed = ROLE_PERMISSIONS.get(r, set())
            return action in allowed
        except ValueError:
            return False

    @staticmethod
    def get_role_permissions(role: str) -> List[str]:
        try:
            r = Role(role.upper())
            return sorted(list(ROLE_PERMISSIONS.get(r, set())))
        except ValueError:
            return []
