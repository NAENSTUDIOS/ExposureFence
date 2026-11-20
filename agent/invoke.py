"""
ExposureFence — Amazon Bedrock AgentCore Invocation Utility
Direct CLI entrypoint for running prompts against the deployed managed harness.
"""

import argparse
import json
import os
import sys

from agent.agentcore_client import AgentCoreClient


def run_invocation(prompt: str, session_id: str = None, region: str = None):
    state_file = os.path.join(os.path.dirname(__file__), "harness_state.json")
    harness_arn = os.getenv("AGENTCORE_HARNESS_ARN")

    if not harness_arn and os.path.exists(state_file):
        try:
            with open(state_file, "r", encoding="utf-8") as f:
                state = json.load(f)
                harness_arn = state.get("harnessArn")
        except Exception:
            pass

    client = AgentCoreClient(
        region_name=region or os.getenv("AWS_DEFAULT_REGION", "us-east-1"),
        harness_arn=harness_arn
    )

    print("=" * 65)
    print("  EXPOSUREFENCE — BEDROCK AGENTCORE INVOCATION")
    print(f"  Region:      {client.region_name}")
    print(f"  Harness ARN: {client.harness_arn or 'NOT SET'}")
    print("=" * 65)

    status = client.get_status()
    if not status.get("aws_credentials_present"):
        print(f"\n[ERROR] AWS Credentials unavailable: {status.get('status_message')}")
        sys.exit(1)

    print(f"\nPrompt: {prompt}")
    print("\nExecuting AgentCore Converse stream & inline tool loop...")

    try:
        res = client.invoke(prompt=prompt, runtime_session_id=session_id)
        print("\n" + "-" * 40)
        print("AGENT RESPONSE:")
        print("-" * 40)
        print(res.get("response", "(No textual response)"))

        print("\n" + "-" * 40)
        print(f"EXECUTED TOOLS ({len(res.get('executed_tools', []))}):")
        print("-" * 40)
        for t in res.get("executed_tools", []):
            print(f"- Tool: {t['tool']} | Status: {t['status']}")
            if "result" in t:
                print(f"  Result: {json.dumps(t['result'], indent=2)}")
            if "error" in t:
                print(f"  Error:  {t['error']}")

        print(f"\nSession ID: {res.get('session_id')}")
        print(f"Turns:      {res.get('turns')}")

    except Exception as e:
        print(f"\n[ERROR] Invocation failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Invoke ExposureFence AgentCore Harness")
    parser.add_argument("prompt", type=str, help="Prompt text to send to the agent")
    parser.add_argument("--session", type=str, default=None, help="Runtime session ID")
    parser.add_argument("--region", type=str, default=None, help="AWS Region")

    args = parser.parse_args()
    run_invocation(args.prompt, args.session, args.region)
