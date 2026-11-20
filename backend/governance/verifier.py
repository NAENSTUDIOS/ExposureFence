"""
ExposureFence — Independent Post-Action Verification Engine
Independently verifies that an executed remediation actually resolved the exposure.
Prevents false claims of compliance by inspecting ground-truth post-remediation evidence.
"""

from typing import Any, Dict, Tuple


class IndependentPostActionVerifier:
    """
    Independent test oracle verifying whether the target resource is in the desired secure state.
    Directly satisfies Scenario 6 (Independent Verification Failure).
    """

    @staticmethod
    def verify_remediation(
        resource_arn: str,
        action_type: str,
        post_execution_state: Dict[str, Any]
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Re-evaluates the ground-truth post-execution state.
        Returns: (is_verified: bool, reason: str, verification_details: dict)
        """
        if action_type == "enable_s3_block_public_access":
            bpa = post_execution_state.get("block_public_access", {})
            is_effective = bpa.get("is_effective", False) or all([
                bpa.get("BlockPublicAcls", False),
                bpa.get("IgnorePublicAcls", False),
                bpa.get("BlockPublicPolicy", False),
                bpa.get("RestrictPublicBuckets", False)
            ])
            is_public_policy = post_execution_state.get("is_public_policy", False)

            if is_effective and not is_public_policy:
                return True, "Verified: S3 Block Public Access is effective and public policy removed.", {"is_effective": True}
            else:
                return False, "Verification Failed: S3 bucket remains publicly accessible in post-execution state.", {
                    "is_effective": is_effective,
                    "is_public_policy": is_public_policy
                }

        elif action_type == "revoke_security_group_ingress":
            ingress_rules = post_execution_state.get("ingress_rules", [])
            has_open_ssh = False
            for r in ingress_rules:
                if (r.get("cidr_ipv4") == "0.0.0.0/0" or r.get("cidr_ipv6") == "::/0") and (r.get("from_port") == 22 or r.get("to_port") == 22):
                    has_open_ssh = True
                    break

            if not has_open_ssh:
                return True, "Verified: Unrestricted SSH ingress rule successfully removed.", {"has_open_ssh": False}
            else:
                return False, "Verification Failed: Security group still contains unrestricted ingress on port 22.", {"has_open_ssh": True}

        elif action_type == "detach_admin_role_policy":
            policies = post_execution_state.get("attached_policies", [])
            has_admin = any(p.get("policy_name") == "AdministratorAccess" for p in policies)

            if not has_admin:
                return True, "Verified: AdministratorAccess policy successfully detached.", {"has_admin": False}
            else:
                return False, "Verification Failed: AdministratorAccess policy remains attached.", {"has_admin": True}

        return False, f"Verification Failed: Unknown or unsupported action type '{action_type}'.", {}
