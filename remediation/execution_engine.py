import hashlib
import json
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TERRAFORM_DIR = PROJECT_ROOT / "aws-s3-baseline"

PROPOSAL_PATH = (
    PROJECT_ROOT / "remediation" / "proposals" / "s3_tls_proposal.json"
)

CATALOG_PATH = (
    PROJECT_ROOT / "remediation" / "catalog" / "s3_require_tls.json"
)

ACCOUNT_ID = "665808487090"
REGION = "us-east-1"
BUCKET_NAME = "cloud-remediation-mvp-848f82dd"
BUCKET_ARN = f"arn:aws:s3:::{BUCKET_NAME}"
TERRAFORM_ADDRESS = "aws_s3_bucket.test"

PLAN_PATH = TERRAFORM_DIR / "s3-tls-remediation.tfplan"
AUDIT_PATH = PROJECT_ROOT / "remediation" / "audit" / "execution_events.jsonl"


def load_json(path):
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def validate_proposal():
    """Validate that the proposal authorizes planning for the expected target."""

    if not PROPOSAL_PATH.exists():
        raise ValueError("S3.5 proposal file does not exist.")

    proposal = load_json(PROPOSAL_PATH)
    catalog = load_json(CATALOG_PATH)

    if proposal.get("proposal_id") != "PROP-AWS-S3-TLS-E9F63A9D911C":
        raise ValueError("Unexpected proposal ID.")

    if proposal.get("test_fixture") is not False:
        raise ValueError("Only a real finding proposal is permitted.")

    if proposal.get("proposal_status") != "DRAFT":
        raise ValueError("Proposal must remain in DRAFT status.")

    if proposal.get("execution_status") != "NOT_EXECUTED":
        raise ValueError("Proposal has an unexpected execution status.")

    if proposal.get("finding", {}).get("security_control_id") != "S3.5":
        raise ValueError("Proposal is not for S3.5.")

    if proposal.get("finding", {}).get("compliance_status") != "FAILED":
        raise ValueError("S3.5 finding is no longer FAILED.")

    resource = proposal.get("affected_resource", {})

    if resource.get("account_id") != ACCOUNT_ID:
        raise ValueError("Unexpected AWS account.")

    if resource.get("region") != REGION:
        raise ValueError("Unexpected AWS region.")

    if resource.get("resource_id") != BUCKET_ARN:
        raise ValueError("Unexpected S3 bucket.")

    management = proposal.get("management_context", {})

    if management.get("management_mechanism") != "terraform":
        raise ValueError("Target is not managed by Terraform.")

    if management.get("terraform_management_status") != (
        "confirmed_in_current_state"
    ):
        raise ValueError("Terraform management is not confirmed.")

    if management.get("terraform_resource_address") != TERRAFORM_ADDRESS:
        raise ValueError("Unexpected Terraform resource address.")

    if proposal.get("recommended_remediation", {}).get("catalog_id") != (
        catalog.get("catalog_id")
    ):
        raise ValueError("Proposal catalog does not match.")

    governance = proposal.get("governance", {})

    if governance.get("execution_allowed") is not False:
        raise ValueError("Proposal must not independently authorize execution.")

    if governance.get("approval_required") is not True:
        raise ValueError("Proposal must require human approval.")

    if proposal.get("risk_assessment", {}).get(
        "unresolved_prerequisites"
    ):
        raise ValueError("Proposal has unresolved prerequisites.")

    return proposal


def verify_aws_identity():
    """Confirm the AWS CLI is operating in the expected account."""

    command = [
        "aws", "sts", "get-caller-identity",
        "--query", "Account",
        "--output", "text",
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip())

    actual_account = result.stdout.strip()

    if actual_account != ACCOUNT_ID:
        raise ValueError(
            f"AWS account mismatch: expected {ACCOUNT_ID}, "
            f"received {actual_account}."
        )

    return actual_account


def verify_terraform_state():
    """Confirm the target bucket is present at the expected state address."""

    command = [
        "terraform",
        f"-chdir={TERRAFORM_DIR}",
        "state",
        "show",
        TERRAFORM_ADDRESS,
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError(
            "Could not confirm the Terraform resource: "
            + result.stderr.strip()
        )

    if BUCKET_NAME not in result.stdout:
        raise ValueError("Terraform state does not contain the expected bucket.")

    return True


def add_tls_policy_configuration():
    """Add the S3.5 policy to Terraform without overwriting existing resources."""

    main_tf = TERRAFORM_DIR / "main.tf"
    source = main_tf.read_text(encoding="utf-8")

    resource_header = 'resource "aws_s3_bucket_policy" "test"'

    if resource_header in source:
        raise ValueError(
            "The source bucket policy resource already exists. "
            "Refusing to modify Terraform configuration."
        )

    tls_resource = '''

# MVP remediation: Require TLS for all source bucket requests.
resource "aws_s3_bucket_policy" "test" {
  bucket = aws_s3_bucket.test.id

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"

        Resource = [
          aws_s3_bucket.test.arn,
          "${aws_s3_bucket.test.arn}/*"
        ]

        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}
'''

    main_tf.write_text(
        source.rstrip() + "\n" + tls_resource,
        encoding="utf-8",
    )

    print("TLS bucket policy added to Terraform configuration.")


def run_terraform_command(arguments):
    """Run a Terraform command and stop if it fails."""

    command = [
        "terraform",
        f"-chdir={TERRAFORM_DIR}",
        *arguments,
    ]

    print("\nRunning:", " ".join(command))

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
    )

    if result.stdout:
        print(result.stdout)

    if result.returncode != 0:
        if result.stderr:
            print(result.stderr, file=sys.stderr)
        raise RuntimeError("Terraform command failed.")

    return result.stdout


def generate_terraform_plan():
    """Format, validate, and generate a saved Terraform plan."""

    run_terraform_command(["fmt", "-check"])
    run_terraform_command(["validate"])

    if PLAN_PATH.exists():
        PLAN_PATH.unlink()

    run_terraform_command([
        "plan",
        "-input=false",
        "-out=s3-tls-remediation.tfplan",
    ])

    print("\nSaved Terraform plan:", PLAN_PATH)
    print("AWS resources have NOT been modified.")


def verify_current_s3_5_finding():
    """Confirm Security Hub still reports S3.5 as FAILED."""

    command = [
        "aws", "securityhub", "get-findings",
        "--region", REGION,
        "--filters", json.dumps({
            "Id": [{
                "Value": (
                    "arn:aws:securityhub:us-east-1:665808487090:"
                    "security-control/S3.5/finding/"
                    "9818dc26-133f-4e44-926c-4fc3079dbfcb"
                ),
                "Comparison": "EQUALS",
            }]
        }),
        "--output", "json",
    ]

    result = subprocess.run(
        command, capture_output=True, text=True, check=False
    )

    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip())

    findings = json.loads(result.stdout).get("Findings", [])

    if len(findings) != 1:
        raise ValueError("Could not confirm the exact S3.5 finding.")

    finding = findings[0]

    if finding.get("Compliance", {}).get("Status") != "FAILED":
        raise ValueError("S3.5 is no longer FAILED. Execution stopped.")

    if finding.get("RecordState") != "ACTIVE":
        raise ValueError("S3.5 finding is no longer active.")

    return finding


def verify_no_existing_source_policy():
    """Stop if a source bucket policy already exists."""

    command = [
        "aws", "s3api", "get-bucket-policy",
        "--bucket", BUCKET_NAME,
        "--region", REGION,
        "--output", "json",
    ]

    result = subprocess.run(
        command, capture_output=True, text=True, check=False
    )

    if result.returncode == 0:
        raise ValueError(
            "A bucket policy now exists. Refusing to overwrite it."
        )

    if "NoSuchBucketPolicy" not in result.stderr:
        raise RuntimeError(
            "Could not safely determine the current bucket policy: "
            + result.stderr.strip()
        )


def inspect_saved_plan():
    """Allow only the exact one-resource creation in the reviewed plan."""

    if not PLAN_PATH.is_file():
        raise ValueError("Saved Terraform plan does not exist.")

    command = [
        "terraform",
        f"-chdir={TERRAFORM_DIR}",
        "show",
        "-json",
        str(PLAN_PATH),
    ]

    result = subprocess.run(
        command, capture_output=True, text=True, check=False
    )

    if result.returncode != 0:
        raise RuntimeError(
            "Could not inspect saved Terraform plan: "
            + result.stderr.strip()
        )

    plan = json.loads(result.stdout)
    changes = plan.get("resource_changes", [])

    meaningful_changes = [
        item for item in changes
        if item.get("change", {}).get("actions") != ["no-op"]
    ]

    if len(meaningful_changes) != 1:
        raise ValueError(
            "Plan must contain exactly one non-no-op resource change."
        )

    change = meaningful_changes[0]

    if change.get("address") != "aws_s3_bucket_policy.test":
        raise ValueError("Unexpected Terraform resource in saved plan.")

    if change.get("type") != "aws_s3_bucket_policy":
        raise ValueError("Unexpected Terraform resource type.")

    if change.get("change", {}).get("actions") != ["create"]:
        raise ValueError("Only a new bucket policy creation is permitted.")

    after = change.get("change", {}).get("after", {})

    if after.get("bucket") != BUCKET_NAME:
        raise ValueError("Plan targets an unexpected bucket.")

    policy_text = after.get("policy", "")

    try:
        policy = json.loads(policy_text)
    except (TypeError, json.JSONDecodeError):
        raise ValueError("Could not validate planned bucket policy.")

    statements = policy.get("Statement", [])

    if isinstance(statements, dict):
        statements = [statements]

    expected_resources = {
        BUCKET_ARN,
        f"{BUCKET_ARN}/*",
    }

    matching_statements = [
        statement for statement in statements
        if statement.get("Sid") == "DenyInsecureTransport"
        and statement.get("Effect") == "Deny"
        and statement.get("Principal") == "*"
        and statement.get("Action") == "s3:*"
        and statement.get("Condition", {}).get("Bool", {}).get(
            "aws:SecureTransport"
        ) == "false"
        and set(
            statement.get("Resource", [])
            if isinstance(statement.get("Resource"), list)
            else [statement.get("Resource")]
        ) == expected_resources
    ]

    if len(matching_statements) != 1:
        raise ValueError("Planned TLS policy does not match expectations.")

    return hashlib.sha256(PLAN_PATH.read_bytes()).hexdigest()


def verify_plan_integrity(expected_hash):
    """Confirm the saved plan has not changed since inspection."""

    if not PLAN_PATH.is_file():
        raise ValueError("Saved Terraform plan does not exist.")

    actual_hash = hashlib.sha256(PLAN_PATH.read_bytes()).hexdigest()

    if actual_hash != expected_hash:
        raise ValueError(
            "Saved Terraform plan changed after inspection. "
            "Execution is cancelled."
        )

    return True


def verify_applied_tls_policy():
    """Verify the actual AWS bucket policy after execution."""

    command = [
        "aws", "s3api", "get-bucket-policy",
        "--bucket", BUCKET_NAME,
        "--region", REGION,
        "--output", "json",
    ]

    result = subprocess.run(
        command, capture_output=True, text=True, check=False
    )

    if result.returncode != 0:
        raise RuntimeError(
            "Could not retrieve the applied bucket policy: "
            + result.stderr.strip()
        )

    response = json.loads(result.stdout)
    policy = json.loads(response["Policy"])

    statements = policy.get("Statement", [])

    if isinstance(statements, dict):
        statements = [statements]

    expected_resources = {BUCKET_ARN, f"{BUCKET_ARN}/*"}

    for statement in statements:
        resources = statement.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]

        if (
            statement.get("Sid") == "DenyInsecureTransport"
            and statement.get("Effect") == "Deny"
            and statement.get("Principal") == "*"
            and statement.get("Action") == "s3:*"
            and str(
                statement.get("Condition", {}).get("Bool", {}).get(
                "aws:SecureTransport"
                )
            ).lower() == "false"
            and set(resources) == expected_resources
        ):
            return True

    raise RuntimeError(
        "AWS returned a bucket policy, but the expected TLS protection "
        "was not found."
    )


def append_execution_audit(event):
    AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)

    with AUDIT_PATH.open("a", encoding="utf-8") as file:
        file.write(json.dumps(event) + "\n")


def execute_saved_plan(proposal):
    """Require explicit approval and apply only the inspected saved plan."""

    print("\n=== FINAL EXECUTION SAFETY CHECKS ===")

    verify_aws_identity()
    verify_terraform_state()
    verify_current_s3_5_finding()
    verify_no_existing_source_policy()

    plan_hash = inspect_saved_plan()

    print("AWS account: CONFIRMED")
    print("Terraform resource: CONFIRMED")
    print("Security Hub S3.5: STILL FAILED")
    print("Source bucket policy: ABSENT")
    print("Saved plan: EXACT EXPECTED CHANGE")
    print(f"SHA-256: {plan_hash}")

    print("\n=== CHANGE TO BE EXECUTED ===")
    print(f"Bucket: {BUCKET_NAME}")
    print("Action: Create one S3 bucket policy")
    print("Effect: Deny requests without TLS")
    print("HTTPS requests: Not denied by this statement")
    print("Resources: 1 create, 0 change, 0 destroy")

    print("\nTo authorize this exact plan, type:")
    print(proposal["proposal_id"])


    approval = input("\nExecution approval: ").strip()

    if approval != proposal["proposal_id"]:
        event = {
            "event_type": "EXECUTION_CANCELLED",
            "execution_id": str(uuid.uuid4()),
            "proposal_id": proposal["proposal_id"],
            "finding_id": proposal["finding"]["finding_id"],
            "resource_id": BUCKET_ARN,
            "aws_account": ACCOUNT_ID,
            "region": REGION,
            "plan_sha256": plan_hash,
            "execution_status": "CANCELLED",
            "cancellation_reason": "PROPOSAL_ID_CONFIRMATION_MISMATCH",
            "completed_at": datetime.now(timezone.utc).isoformat(),
        }

        append_execution_audit(event)

        print("Approval did not match. Execution cancelled.")
        return

    event = {
        "execution_id": str(uuid.uuid4()),
        "proposal_id": proposal["proposal_id"],
        "finding_id": proposal["finding"]["finding_id"],
        "resource_id": BUCKET_ARN,
        "aws_account": ACCOUNT_ID,
        "region": REGION,
        "plan_sha256": plan_hash,
        "approved_by": "interactive_proposal_id_confirmation",
        "approved_at": datetime.now(timezone.utc).isoformat(),
        "execution_status": "STARTED",
        "execution_method": "terraform_apply_saved_plan",
    }


    print("\nApplying the exact reviewed Terraform plan...")

    try:
        verify_plan_integrity(plan_hash)
    except ValueError as error:
        event["event_type"] = "EXECUTION_ABORTED"
        event["execution_status"] = "ABORTED"
        event["abort_reason"] = "SAVED_PLAN_INTEGRITY_FAILURE"
        event["error"] = str(error)
        event["completed_at"] = datetime.now(timezone.utc).isoformat()

        append_execution_audit(event)

        print(f"Execution aborted: {error}")
        raise

    result = subprocess.run(
        [
            "terraform",
            f"-chdir={TERRAFORM_DIR}",
            "apply",
            "-input=false",
            str(PLAN_PATH),
        ],
        text=True,
        check=False,
    )

    if result.returncode != 0:
        event["execution_status"] = "FAILED"
        event["completed_at"] = datetime.now(timezone.utc).isoformat()
        append_execution_audit(event)
        raise RuntimeError("Terraform apply failed. Review its output.")

    event["execution_status"] = "APPLIED"

    print("\nTerraform apply succeeded. Verifying AWS configuration...")

    try:
        verify_applied_tls_policy()
        event["verification_status"] = "COMPLIANT"
        print("AWS bucket policy verification: COMPLIANT")

    except (RuntimeError, ValueError, KeyError, json.JSONDecodeError) as error:
        event["verification_status"] = "FAILED"
        event["verification_error"] = str(error)
        raise

    finally:
        event["completed_at"] = datetime.now(timezone.utc).isoformat()
        append_execution_audit(event)

    print("\nMVP EXECUTION SUCCESSFUL")
    print(f"Proposal: {proposal['proposal_id']}")
    print(f"Audit record: {AUDIT_PATH}")
    print("Security Hub reassessment must still be checked.")



def main():
    print("Validating S3.5 remediation proposal...")
    proposal = validate_proposal()
    print(f"Proposal validated: {proposal['proposal_id']}")

    print("\nChecking AWS account...")
    account = verify_aws_identity()
    print(f"AWS account confirmed: {account}")

    print("\nChecking Terraform management...")
    verify_terraform_state()
    print(f"Terraform resource confirmed: {TERRAFORM_ADDRESS}")

    execute_saved_plan(proposal)



if __name__ == "__main__":
    try:
        main()
    except (ValueError, RuntimeError, OSError, json.JSONDecodeError) as error:
        print(f"VALIDATION FAILED: {error}", file=sys.stderr)
        sys.exit(1)
