"""
AgentCore Inline Function Tool Definitions for ExposureFence.
These schemas match the tool handoff contract expected by Amazon Bedrock AgentCore.
"""

INLINE_TOOL_DEFINITIONS = [
    {
        "name": "read_mock_s3",
        "description": "Read approved synthetic AWS S3 bucket configurations for security analysis.",
        "inputSchema": {
            "json": {
                "type": "object",
                "properties": {},
                "additionalProperties": False
            }
        }
    },
    {
        "name": "read_mock_security_groups",
        "description": "Read approved synthetic AWS EC2 security-group ingress rules for security analysis.",
        "inputSchema": {
            "json": {
                "type": "object",
                "properties": {},
                "additionalProperties": False
            }
        }
    },
    {
        "name": "propose_fix",
        "description": "Submit a safe remediation fix proposal for a validated security finding. Creates a PENDING proposal for human review.",
        "inputSchema": {
            "json": {
                "type": "object",
                "properties": {
                    "finding_id": {
                        "type": "string",
                        "description": "The validated finding identifier (e.g. F-S3-001 or F-SG-001)"
                    }
                },
                "required": ["finding_id"],
                "additionalProperties": False
            }
        }
    }
]
