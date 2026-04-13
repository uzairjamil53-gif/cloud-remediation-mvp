import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent
OUTPUT_FILE = Path(__file__).resolve().parent / "securityhub_findings.json"

AWS_REGION = "us-east-1"
MAX_FINDINGS = 100

# Map known AWS Security Hub resource types to a more portable
# CloudFormation-style resource type. Preserve unknown types unchanged.
RESOURCE_TYPE_MAP = {
    "AwsS3Bucket": "AWS::S3::Bucket",
    "AwsEc2Vpc": "AWS::EC2::VPC",
    "AwsEc2Instance": "AWS::EC2::Instance",
    "AwsEc2SecurityGroup": "AWS::EC2::SecurityGroup",
    "AwsEc2Subnet": "AWS::EC2::Subnet",
}


def run_command(args):
    """Run a local command and return its standard output."""
    result = subprocess.run(
        args,
        cwd=PROJECT_DIR,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout


def aws_json(*args):
    """Run an AWS CLI command and parse its JSON output."""
    output = run_command(
        ["aws", *args, "--output", "json"]
    )
    return json.loads(output)


def valid_account_id(value):
    """Return a 12-digit AWS account ID, or None if unavailable."""
    if isinstance(value, str) and re.fullmatch(r"\d{12}", value):
        return value
    return None


def account_from_arn(arn):
    """Extract an AWS account ID from an ARN when present."""
    if not isinstance(arn, str) or not arn.startswith("arn:"):
        return None

    parts = arn.split(":")
    if len(parts) > 4:
        return valid_account_id(parts[4])

    return None


def normalize_resource(resource, finding_region):
    """Normalize one affected resource without discarding source data."""
    resource_type = resource.get("Type")
    resource_id = resource.get("Id")

    owner = resource.get("Owner") or {}
    owner_account = (owner.get("Account") or {}).get("Id")

    account_id = (
        valid_account_id(owner_account)
        or account_from_arn(resource_id)
    )

    region = resource.get("Region") or account_region_from_arn(resource_id)
    region = region or finding_region

    is_account_resource = resource_type == "AwsAccount"

    return {
        "cloud_provider": "aws",
        "account_id": account_id,
        "resource_scope": "account" if is_account_resource else "resource",
        "resource_type": RESOURCE_TYPE_MAP.get(
            resource_type, resource_type
        ),
        "source_resource_type": resource_type,
        "resource_id": resource_id,
        "region": region,
        "arn": resource_id if isinstance(resource_id, str)
        and resource_id.startswith("arn:") else None,
    }


def account_region_from_arn(arn):
    """Extract the region field from an ARN when available."""
    if not isinstance(arn, str) or not arn.startswith("arn:"):
        return None

    parts = arn.split(":")
    if len(parts) > 3 and parts[3]:
        return parts[3]

    return None


def normalize_finding(finding, collector_account_id):
    """Create a portable finding record while preserving its raw source."""
    resources = [
        normalize_resource(resource, AWS_REGION)
        for resource in finding.get("Resources", [])
    ]

    account_id = valid_account_id(finding.get("AwsAccountId"))

    if account_id is None:
        resource_accounts = {
            resource["account_id"]
            for resource in resources
            if resource["account_id"] is not None
        }

        if len(resource_accounts) == 1:
            account_id = next(iter(resource_accounts))

    # Do not silently assign the collector's account to a finding that
    # may belong to a different account.
    resource_scopes = {resource["resource_scope"] for resource in resources}

    if not resources or resource_scopes == {"account"}:
        finding_scope = "account"
    elif "resource" in resource_scopes:
        finding_scope = "resource"
    else:
        finding_scope = "unknown"

    severity = finding.get("Severity") or {}
    workflow = finding.get("Workflow") or {}
    compliance = finding.get("Compliance") or {}
    remediation = finding.get("Remediation") or {}

    return {
        "finding_id": finding.get("Id"),
        "source_provider": "aws_security_hub",
        "cloud_provider": "aws",
        "account_id": account_id,
        "collector_account_id": collector_account_id,
        "region": finding.get("Region") or AWS_REGION,
        "finding_scope": finding_scope,
        "title": finding.get("Title"),
        "description": finding.get("Description"),
        "severity": severity.get("Label"),
        "severity_normalized": severity.get("Normalized"),
        "workflow_status": workflow.get("Status"),
        "compliance_status": compliance.get("Status"),
        "security_control_id": compliance.get("SecurityControlId"),
        "generator_id": finding.get("GeneratorId"),
        "product_arn": finding.get("ProductArn"),
        "record_state": finding.get("RecordState"),
        "first_observed_at": finding.get("FirstObservedAt"),
        "last_observed_at": finding.get("LastObservedAt"),
        "created_at": finding.get("CreatedAt"),
        "updated_at": finding.get("UpdatedAt"),
        "remediation": remediation,
        "resources": resources,
        "raw_source_finding": finding,
    }


def main():
    # Verify which AWS identity is collecting the findings.
    identity = aws_json(
        "sts",
        "get-caller-identity",
        "--region",
        AWS_REGION,
    )
    collector_account_id = identity["Account"]

    # Read up to MAX_FINDINGS findings. AWS CLI pagination is bounded
    # by --max-items; no finding or resource is modified.
    response = aws_json(
        "securityhub",
        "get-findings",
        "--region",
        AWS_REGION,
        "--max-items",
        str(MAX_FINDINGS),
    )

    raw_findings = response.get("Findings", [])

    normalized_findings = [
        normalize_finding(finding, collector_account_id)
        for finding in raw_findings
    ]

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_provider": "aws_security_hub",
        "collector_account_id": collector_account_id,
        "region": AWS_REGION,
        "finding_count": len(normalized_findings),
        "max_findings_requested": MAX_FINDINGS,
        "next_token_available": bool(response.get("NextToken")),
        "findings": normalized_findings,
    }

    OUTPUT_FILE.write_text(
        json.dumps(report, indent=2) + "\n",
        encoding="utf-8",
    )

    account_level = sum(
        finding["finding_scope"] == "account"
        for finding in normalized_findings
    )
    resource_level = sum(
        finding["finding_scope"] == "resource"
        for finding in normalized_findings
    )

    print(f"AWS account verified: {collector_account_id}")
    print(f"Region: {AWS_REGION}")
    print(f"Findings retrieved: {len(normalized_findings)}")
    print(f"Account-level findings: {account_level}")
    print(f"Resource-level findings: {resource_level}")
    print(f"Output written to: {OUTPUT_FILE}")

    if response.get("NextToken"):
        print(
            "More findings may be available. "
            "This run was limited to the configured maximum."
        )


if __name__ == "__main__":
    main()
