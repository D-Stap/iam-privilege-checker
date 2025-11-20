#!/usr/bin/env python3

import argparse
import fnmatch
import json
import sys
from typing import Any, Dict, List

# Patterns considered high-risk actions
HIGH_RISK_ACTIONS = [
    "iam:*",
    "ec2:*",
    "s3:PutObject",
    "s3:DeleteObject",
    "s3:PutBucketAcl",
    "s3:PutBucketPolicy",
    "kms:*"
]

# Load policy JSON from file or stdin
def load_policy(path: str) -> Dict[str, Any]:
    if path == "-":
        return json.load(sys.stdin)
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

# Check if action matches any high-risk patterns
def actin_is_high_risk(action):
    # Fully wildcarded actions like "*"
    if action == "*":
        return True

    # IAM, KMS, EC2 full access always high risk
    if any(action.lower().startswith(svc.lower().replace("*", "")) and action.endswith("*")
           for svc in ["iam:*", "kms:*", "ec2:*"]):
        return True

    # Specific high risk S3 actions (writing or privilege escalation)
    risky_s3_actions = [
        "s3:putobject",
        "s3:deleteobject",
        "s3:putbucketacl",
        "s3:putbucketpolicy"
    ]
    if action.lower() in risky_s3_actions:
        return True

    return False


# Analyze policy object for high-risk actions and wildcard resources
def analyze_policy_obj(policy: Dict[str, Any]) -> List[str]:
    findings: List[str] = []

    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for statement in statements:
        actions = statement.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]

        for action in actions:
            try:
                if action_is_high_risk(action):
                    findings.append(f"High Risk: action '{action}' matches risky pattern")
            except Exception:
                # be defensive: treat unknown formats as non-matching
                continue

        resources = statement.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]
        if "*" in resources:
            findings.append("Resource '*' found — full access to all resources")

    return findings


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Quick IAM policy checker")
    parser.add_argument("policy", help="Path to policy JSON file, or '-' to read from stdin")
    parser.add_argument("-q", "--quiet", action="store_true", help="Only set exit code, minimal output")
    parser.add_argument("--json", action="store_true", help="Output findings as JSON")
    args = parser.parse_args(argv)

    try:
        policy = load_policy(args.policy)
    except Exception as e:
        print(f"Error loading policy '{args.policy}': {e}", file=sys.stderr)
        return 2

    findings = analyze_policy_obj(policy)

    if args.json:
        out = {"policy": args.policy, "findings": findings}
        print(json.dumps(out, indent=2))
    else:
        if not args.quiet:
                print(f"Analyzing IAM policy: {args.policy}\n")
                if findings:
                    for f in findings:
                        print("FINDING:", f)
                else:
                    print("No excessive permissions found")
                print("\nScan complete.\n")

    # exit code: 0 = no findings, 3 = findings present, 2 = load error
    return 0 if not findings else 3


if __name__ == "__main__":
    rc = main()
    sys.exit(rc)
