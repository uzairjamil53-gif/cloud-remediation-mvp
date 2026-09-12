import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

OUTPUT_PATH = (
    PROJECT_ROOT
    / "remediation"
    / "proposals"
    / "s3_tls_verification.json"
)

REGION = "us-east-1"
ACCOUNT_ID = "665808487090"
BUCKET_NAME = "cloud-remediation-mvp-848f82dd"
EXPECTED_FINDING_ID = (
    "arn:aws:securityhub:us-east-1:665808487090:"
    "security-control/S3.5/finding/"
    "9818dc26-133f-4e44-926c-4fc3079dbfcb"
)


def run_aws_command(command):
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        return None, result.stderr.strip() or "AWS CLI request failed."

    return result.stdout, None


def get_bucket_policy():
    command = [
        "aws", "s3api", "get-bucket-policy",
        "--bucket", BUCKET_NAME,
        "--region", REGION,
        "--output", "json",
    ]

    output, error = run_aws_command(command)

    if error:
        if "NoSuchBucketPolicy" in error:
            return None, None
        return None, error

    try:
        response = json.loads(output)
        policy = json.loads(response["Policy"])
    except (json.JSONDecodeError, KeyError, TypeError):
        return None, "Could not parse the bucket policy response."

    if not isinstance(policy, dict):
        return None, "Bucket policy is not a JSON object."

    return policy, None


def has_tls_deny(policy):
    if not isinstance(policy, dict):
        return False

    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    expected_resources = {
        f"arn:aws:s3:::{BUCKET_NAME}",
        f"arn:aws:s3:::{BUCKET_NAME}/*",
    }

    for statement in statements:
        if not isinstance(statement, dict):
            continue

        if statement.get("Effect") != "Deny":
            continue

        condition = statement.get("Condition", {})
        bool_condition = condition.get("Bool", {})

        if bool_condition.get("aws:SecureTransport") is not False:
            continue

        resources = statement.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]

        if expected_resources.issubset(set(resources)):
            return True

    return False


def main():
    policy, error = get_bucket_policy()

    if error:
        status = "UNKNOWN"
        tls_required = None
    else:
        tls_required = has_tls_deny(policy)
        status = "COMPLIANT" if tls_required else "NON_COMPLIANT"

    evidence = {
        "verification_type": "live_s3_tls_configuration",
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "status": status,
        "finding": {
            "finding_id": EXPECTED_FINDING_ID,
            "security_control_id": "S3.5",
        },
        "resource": {
            "bucket_name": BUCKET_NAME,
            "resource_id": f"arn:aws:s3:::{BUCKET_NAME}",
            "resource_type": "AWS::S3::Bucket",
            "region": REGION,
            "account_id": ACCOUNT_ID,
        },
        "live_configuration": {
            "tls_required": tls_required,
            "policy_present": policy is not None,
        },
        "evidence_source": "aws s3api get-bucket-policy",
        "read_only": True,
        "execution_allowed": False,
        "error": error,
        "limitations": [
            "This checks for an explicit TLS-deny statement covering "
            "the bucket and its objects.",
            "It does not test actual HTTP or HTTPS client requests.",
            "It does not execute remediation.",
            "Security Hub reassessment is a separate validation step.",
        ],
    }

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(
        json.dumps(evidence, indent=2) + "\n",
        encoding="utf-8",
    )

    print(json.dumps(evidence, indent=2))


if __name__ == "__main__":
    main()
