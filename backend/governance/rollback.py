"""
ExposureFence — Remediation Rollback Plan Generator
Generates deterministic inverse actions and rollback specifications for approved remediations.
"""

import hashlib
import json
from typing import Any, Dict


class RollbackPlanGenerator:
    """Computes exact rollback action definitions and parameter envelopes."""

    @staticmethod
    def generate_rollback(action_type: str, resource_arn: str, parameters: Dict[str, Any], prior_state: Dict[str, Any] = None) -> Dict[str, Any]:
        prior = prior_state or {}

        if action_type == "enable_s3_block_public_access":
            rollback_action = "restore_previous_s3_public_access_block"
            rollback_params = {
                "bucket_name": parameters.get("bucket_name") or resource_arn.split(":::")[-1],
                "previous_configuration": prior.get("previous_block_public_access", {
                    "BlockPublicAcls": False,
                    "IgnorePublicAcls": False,
                    "BlockPublicPolicy": False,
                    "RestrictPublicBuckets": False
                })
            }
        elif action_type == "revoke_security_group_ingress":
            rollback_action = "restore_security_group_ingress_rule"
            rollback_params = {
                "group_id": parameters.get("group_id") or resource_arn.split("/")[-1],
                "ip_permissions": parameters.get("revoked_permissions", [
                    {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
                ])
            }
        elif action_type == "detach_admin_role_policy":
            rollback_action = "re_attach_role_policy"
            rollback_params = {
                "role_name": parameters.get("role_name") or resource_arn.split("/")[-1],
                "policy_arn": parameters.get("policy_arn", "arn:aws:iam::aws:policy/AdministratorAccess")
            }
        else:
            rollback_action = "generic_rollback"
            rollback_params = {"target_resource": resource_arn, "revert_parameters": parameters}

        canonical_repr = {"action": rollback_action, "params": rollback_params, "resource": resource_arn}
        digest = hashlib.sha256(json.dumps(canonical_repr, sort_keys=True).encode("utf-8")).hexdigest()

        return {
            "rollback_action": rollback_action,
            "parameters": rollback_params,
            "rollback_digest": digest
        }
