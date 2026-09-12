import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

PROJECT_ROOT = Path(__file__).resolve().parent.parent

CATALOG_PATH = PROJECT_ROOT / "remediation/catalog/s3_require_tls.json"
INVENTORY_PATH = PROJECT_ROOT / "inventory/inventory.json"
VERIFICATION_PATH = PROJECT_ROOT / "remediation/proposals/s3_tls_verification.json"
OUTPUT_PATH = PROJECT_ROOT / "remediation/proposals/s3_tls_proposal.json"

REGION = "us-east-1"
ACCOUNT_ID = "665808487090"
BUCKET_NAME = "cloud-remediation-mvp-848f82dd"
RESOURCE_ARN = f"arn:aws:s3:::{BUCKET_NAME}"
TERRAFORM_ADDRESS = "aws_s3_bucket.test"
MAX_EVIDENCE_AGE_SECONDS = 900

FINDING_ID = (
    "arn:aws:securityhub:us-east-1:665808487090:"
    "security-control/S3.5/finding/"
    "9818dc26-133f-4e44-926c-4fc3079dbfcb"
)


def load_json(path):
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def get_finding():
    command = [
        "aws", "securityhub", "get-findings",
        "--region", REGION,
        "--filters",
        json.dumps({
            "Id": [{"Value": FINDING_ID, "Comparison": "EQUALS"}]
        }),
        "--output", "json",
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError(
            result.stderr.strip() or "Unable to retrieve Security Hub finding."
        )

    response = json.loads(result.stdout)
    findings = response.get("Findings", [])

    if len(findings) != 1:
        raise ValueError(
            f"Expected exactly one finding; received {len(findings)}."
        )

    finding = findings[0]

    if finding.get("Id") != FINDING_ID:
        raise ValueError("Finding ID does not match the expected S3.5 finding.")

    if finding.get("AwsAccountId") != ACCOUNT_ID:
        raise ValueError("Finding belongs to an unexpected AWS account.")

    if finding.get("Region") != REGION:
        raise ValueError("Finding belongs to an unexpected AWS region.")

    if finding.get("Compliance", {}).get("SecurityControlId") != "S3.5":
        raise ValueError("Finding is not Security Hub control S3.5.")

    if finding.get("Compliance", {}).get("Status") != "FAILED":
        raise ValueError("S3.5 is no longer FAILED. Refusing to propose remediation.")

    if finding.get("RecordState") != "ACTIVE":
        raise ValueError("Finding is not active.")

    resources = finding.get("Resources", [])

    matches = [
        resource for resource in resources
        if resource.get("Type") == "AwsS3Bucket"
        and resource.get("Id") == RESOURCE_ARN
    ]

    if len(matches) != 1:
        raise ValueError("Finding does not identify exactly the expected bucket.")

    return finding


def find_inventory_resource(inventory):
    resources = (
        inventory if isinstance(inventory, list)
        else inventory.get("resources", [])
    )

    matches = [
        resource for resource in resources
        if resource.get("cloud") == "aws"
        and resource.get("account_id") == ACCOUNT_ID
        and resource.get("region") == REGION
        and resource.get("resource_type") == "AWS::S3::Bucket"
        and resource.get("resource_id") == BUCKET_NAME
    ]

    if len(matches) != 1:
        raise ValueError(
            f"Expected one inventory match; found {len(matches)}."
        )

    resource = matches[0]

    if resource.get("managed_by_terraform") is not True:
        raise ValueError("Inventory does not confirm Terraform management.")

    if resource.get("management_mechanism") != "terraform":
        raise ValueError("Unexpected resource management mechanism.")

    if resource.get("terraform_management_status") != "confirmed_in_current_state":
        raise ValueError("Terraform management is not confirmed in current state.")

    if resource.get("terraform_resource_address") != TERRAFORM_ADDRESS:
        raise ValueError("Terraform resource address does not match.")

    return resource


def validate_verification(verification, finding):
    if verification.get("verification_type") != "live_s3_tls_configuration":
        raise ValueError("Verification type does not match S3 TLS.")

    if verification.get("read_only") is not True:
        raise ValueError("Verification must be read-only.")

    if verification.get("execution_allowed") is not False:
        raise ValueError("Verification must explicitly disable execution.")

    if verification.get("status") != "NON_COMPLIANT":
        raise ValueError("Bucket is no longer verified as NON_COMPLIANT.")

    if verification.get("error") is not None:
        raise ValueError("Live verification contains an AWS error.")

    if verification.get("finding", {}).get("finding_id") != finding.get("Id"):
        raise ValueError("Verification finding ID does not match.")

    resource = verification.get("resource", {})

    if resource.get("bucket_name") != BUCKET_NAME:
        raise ValueError("Verification bucket does not match.")

    if resource.get("account_id") != ACCOUNT_ID:
        raise ValueError("Verification account does not match.")

    if resource.get("region") != REGION:
        raise ValueError("Verification region does not match.")

    configuration = verification.get("live_configuration", {})

    if configuration.get("policy_present") is not False:
        raise ValueError("Expected the live verification to find no bucket policy.")

    if configuration.get("tls_required") is not False:
        raise ValueError("Expected the live verification to find TLS is not required.")

    checked_at = datetime.fromisoformat(
        verification["checked_at"].replace("Z", "+00:00")
    )

    if checked_at.tzinfo is None:
        raise ValueError("Verification timestamp must include a timezone.")

    age = (
        datetime.now(timezone.utc) - checked_at.astimezone(timezone.utc)
    ).total_seconds()

    if age < -60 or age > MAX_EVIDENCE_AGE_SECONDS:
        raise ValueError(
            f"Verification evidence is stale or invalid (age: {age:.0f} seconds). "
            "Run the live verifier again."
        )

    return age


def main():
    catalog = load_json(CATALOG_PATH)
    inventory = load_json(INVENTORY_PATH)
    verification = load_json(VERIFICATION_PATH)

    finding = get_finding()
    inventory_resource = find_inventory_resource(inventory)
    evidence_age = validate_verification(verification, finding)

    unresolved_prerequisites = []

    proposal = {
        "proposal_id": f"PROP-AWS-S3-TLS-{uuid4().hex[:12].upper()}",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "proposal_status": "DRAFT",
        "execution_status": "NOT_EXECUTED",
        "test_fixture": False,
        "evidence_status": "LIVE_VERIFIED",
        "warning": "Proposal only. No AWS configuration has been changed.",
        "finding": {
            "finding_id": finding["Id"],
            "source": "AWS Security Hub",
            "title": finding["Title"],
            "severity": finding["Severity"]["Label"],
            "workflow_status": finding.get("Workflow", {}).get("Status"),
            "compliance_status": finding["Compliance"]["Status"],
            "security_control_id": "S3.5",
            "updated_at": finding.get("UpdatedAt"),
        },
        "affected_resource": {
            "cloud": "aws",
            "account_id": ACCOUNT_ID,
            "region": REGION,
            "resource_type": "AWS::S3::Bucket",
            "resource_id": RESOURCE_ARN,
            "resource_name": BUCKET_NAME,
        },
        "evidence": {
            "status": "NON_COMPLIANT",
            "live_configuration_checked": True,
            "evidence_source": "aws s3api get-bucket-policy",
            "tls_required": False,
            "bucket_policy_present": False,
            "verification_age_seconds": round(evidence_age),
            "verification_issues": [],
        },
        "live_verification": {
            "status": "NON_COMPLIANT",
            "usable_for_decision": True,
            "checked_at": verification["checked_at"],
            "evidence_source": verification["evidence_source"],
        },
        "remediation_decision": {
            "decision": "REMEDIATION_REVIEW_REQUIRED",
            "reason": catalog["remediation"]["summary"],
        },
        "recommended_remediation": {
            "catalog_id": catalog["catalog_id"],
            "summary": catalog["remediation"]["summary"],
            "rationale": catalog["remediation"]["rationale"],
            "desired_configuration": catalog["remediation"]["desired_configuration"],
            "execution_method": "terraform",
        },
        "management_context": {
            "management_mechanism": inventory_resource["management_mechanism"],
            "terraform_management_status": inventory_resource[
                "terraform_management_status"
            ],
            "terraform_resource_address": TERRAFORM_ADDRESS,
            "note": "Terraform management confirmed by current inventory and state.",
        },
        "risk_assessment": {
            "risk_level": catalog["risk_assessment"]["risk_level"],
            "potential_side_effects": catalog["risk_assessment"][
                "potential_side_effects"
            ],
            "preconditions": catalog["risk_assessment"]["preconditions"],
            "unresolved_prerequisites": unresolved_prerequisites,
        },
        "governance": {
            "approval_required": True,
            "approval_status": "PENDING",
            "execution_allowed": False,
        },
        "validation": catalog["validation"],
        "rollback": catalog["rollback"],
    }

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(
        json.dumps(proposal, indent=2) + "\n",
        encoding="utf-8",
    )

    print(f"Proposal generated: {OUTPUT_PATH}")
    print(f"Proposal ID: {proposal['proposal_id']}")
    print(f"Status: {proposal['proposal_status']}")
    print(f"Execution allowed: {proposal['governance']['execution_allowed']}")
    print("AWS resources modified: NO")


if __name__ == "__main__":
    main()
