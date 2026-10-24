import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

OUTPUT_PATH = (
    PROJECT_ROOT
    / "remediation"
    / "proposals"
    / "ec2_default_security_group_verification.json"
)

REGION = "us-east-1"
ACCOUNT_ID = "665808487090"

SECURITY_GROUP_ID = "sg-02feb1c261f4555ab"
SECURITY_GROUP_ARN = (
    "arn:aws:ec2:us-east-1:665808487090:"
    "security-group/sg-02feb1c261f4555ab"
)

VPC_ID = "vpc-0ccb1ae9029082eba"

EXPECTED_FINDING_ID = (
    "arn:aws:securityhub:us-east-1:665808487090:"
    "security-control/EC2.2/finding/"
    "4e15ead1-0009-48f6-9cde-fc9eedf1b46e"
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

    try:
        return json.loads(result.stdout), None
    except json.JSONDecodeError:
        return None, "Could not parse AWS CLI JSON response."


def get_live_finding():
    command = [
        "aws", "securityhub", "get-findings",
        "--region", REGION,
        "--filters",
        json.dumps({
            "Id": [{
                "Value": EXPECTED_FINDING_ID,
                "Comparison": "EQUALS",
            }]
        }),
        "--output", "json",
    ]

    response, error = run_aws_command(command)

    if error:
        return None, error

    findings = response.get("Findings", [])

    if len(findings) != 1:
        return None, (
            f"Expected exactly one finding; received {len(findings)}."
        )

    finding = findings[0]

    compliance = finding.get("Compliance", {})
    workflow = finding.get("Workflow", {})

    if finding.get("Id") != EXPECTED_FINDING_ID:
        return None, "Finding ID mismatch."

    if finding.get("AwsAccountId") != ACCOUNT_ID:
        return None, "Finding account ID mismatch."

    if finding.get("Region") != REGION:
        return None, "Finding region mismatch."

    if compliance.get("SecurityControlId") != "EC2.2":
        return None, "Security control ID mismatch."

    if compliance.get("Status") != "FAILED":
        return None, "Finding compliance status is not FAILED."

    if finding.get("RecordState") != "ACTIVE":
        return None, "Finding record state is not ACTIVE."

    if workflow.get("Status") != "NEW":
        return None, "Finding workflow status is not NEW."

    resource_ids = {
        resource.get("Id")
        for resource in finding.get("Resources", [])
        if resource.get("Id")
    }

    if SECURITY_GROUP_ARN not in resource_ids:
        return None, "Finding resource ARN mismatch."

    return finding, None


def get_security_group():
    command = [
        "aws", "ec2", "describe-security-groups",
        "--region", REGION,
        "--group-ids", SECURITY_GROUP_ID,
        "--output", "json",
    ]

    response, error = run_aws_command(command)

    if error:
        return None, error

    groups = response.get("SecurityGroups", [])

    if len(groups) != 1:
        return None, (
            f"Expected exactly one security group; received {len(groups)}."
        )

    group = groups[0]

    if group.get("GroupId") != SECURITY_GROUP_ID:
        return None, "Security group ID mismatch."

    if group.get("GroupName") != "default":
        return None, "Security group name is not default."

    if group.get("VpcId") != VPC_ID:
        return None, "VPC ID mismatch."

    return group, None


def main():
    finding, finding_error = get_live_finding()
    security_group, group_error = get_security_group()

    errors = []

    if finding_error:
        errors.append(finding_error)

    if group_error:
        errors.append(group_error)

    if errors:
        status = "UNKNOWN"
        inbound_rule_count = None
        outbound_rule_count = None
    else:
        inbound_rule_count = len(
            security_group.get("IpPermissions", [])
        )

        outbound_rule_count = len(
            security_group.get("IpPermissionsEgress", [])
        )

        status = (
            "COMPLIANT"
            if inbound_rule_count == 0
            and outbound_rule_count == 0
            else "NON_COMPLIANT"
        )

    evidence = {
        "verification_type": "live_ec2_default_security_group_configuration",
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "status": status,
        "finding": {
            "finding_id": EXPECTED_FINDING_ID,
            "security_control_id": "EC2.2",
            "compliance_status": (
                finding.get("Compliance", {}).get("Status")
                if finding else None
            ),
            "workflow_status": (
                finding.get("Workflow", {}).get("Status")
                if finding else None
            ),
            "record_state": (
                finding.get("RecordState")
                if finding else None
            ),
            "updated_at": (
                finding.get("UpdatedAt")
                if finding else None
            ),
        },
        "resource": {
            "resource_id": SECURITY_GROUP_ARN,
            "resource_type": "AWS::EC2::SecurityGroup",
            "resource_name": "default",
            "security_group_id": SECURITY_GROUP_ID,
            "vpc_id": VPC_ID,
            "region": REGION,
            "account_id": ACCOUNT_ID,
        },
        "live_configuration": {
            "inbound_rule_count": inbound_rule_count,
            "outbound_rule_count": outbound_rule_count,
            "inbound_rules": (
                security_group.get("IpPermissions")
                if security_group else None
            ),
            "outbound_rules": (
                security_group.get("IpPermissionsEgress")
                if security_group else None
            ),
            "inbound_rules_empty": (
                inbound_rule_count == 0
                if inbound_rule_count is not None else None
            ),
            "outbound_rules_empty": (
                outbound_rule_count == 0
                if outbound_rule_count is not None else None
            ),
        },
        "evidence_source": (
            "aws securityhub get-findings; "
            "aws ec2 describe-security-groups"
        ),
        "read_only": True,
        "execution_allowed": False,
        "error": errors or None,
        "limitations": [
            "This verifies the security group's configured ingress "
            "and egress rules.",
            "It does not prove that no workloads depend on the group.",
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
