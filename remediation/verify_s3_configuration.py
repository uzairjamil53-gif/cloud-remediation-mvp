import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
INVENTORY_PATH = ROOT / "inventory" / "inventory.json"
CATALOG_PATH = (
    ROOT / "remediation" / "catalog"
    / "s3_block_public_access.json"
)
OUTPUT_PATH = (
    ROOT / "remediation" / "proposals"
    / "s3_live_verification.json"
)


def load_json(path):
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def evaluate_configuration(observed, desired):
    """Compare observed AWS settings with the required configuration."""

    aws_names = {
        "block_public_acls": "BlockPublicAcls",
        "ignore_public_acls": "IgnorePublicAcls",
        "block_public_policy": "BlockPublicPolicy",
        "restrict_public_buckets": "RestrictPublicBuckets",
    }

    missing = [
        aws_names[key]
        for key in desired
        if key not in aws_names or aws_names[key] not in observed
    ]

    if missing:
        return "UNKNOWN", missing

    compliant = all(
        observed[aws_names[key]] is desired_value
        for key, desired_value in desired.items()
    )

    if compliant:
        return "COMPLIANT", []

    return "NON_COMPLIANT", []


def main():
    inventory = load_json(INVENTORY_PATH)
    catalog = load_json(CATALOG_PATH)

    matches = [
        resource
        for resource in inventory.get("resources", [])
        if resource.get("resource_type") == "AWS::S3::Bucket"
        and resource.get("management_mechanism") == "terraform"
        and resource.get("terraform_management_status")
        == "confirmed_in_current_state"
        and resource.get("account_id") == inventory.get("account_id")
    ]

    if len(matches) != 1:
        raise RuntimeError(
            "Expected exactly one confirmed Terraform-managed "
            f"S3 bucket in inventory; found {len(matches)}."
        )

    bucket = matches[0]
    region = bucket["region"]

    command = [
        "aws",
        "s3api",
        "get-public-access-block",
        "--bucket",
        bucket["resource_id"],
        "--region",
        region,
        "--output",
        "json",
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
    )

    checked_at = datetime.now(timezone.utc).isoformat()

    if result.returncode != 0:
        verification = {
            "checked_at": checked_at,
            "status": "UNKNOWN",
            "live_configuration_checked": True,
            "cloud": bucket["cloud"],
            "account_id": bucket["account_id"],
            "region": region,
            "resource_id": bucket["resource_id"],
            "error": result.stderr.strip(),
            "note": (
                "The live configuration could not be verified. "
                "Do not interpret an API error as a failed security control."
            ),
        }
    else:
        response = json.loads(result.stdout)
        observed = response.get(
            "PublicAccessBlockConfiguration", {}
        )
        desired = catalog["remediation"]["desired_configuration"]

        status, missing = evaluate_configuration(
            observed, desired
        )

        verification = {
            "checked_at": checked_at,
            "status": status,
            "live_configuration_checked": True,
            "cloud": bucket["cloud"],
            "account_id": bucket["account_id"],
            "region": region,
            "resource_id": bucket["resource_id"],
            "management_mechanism": bucket["management_mechanism"],
            "observed_configuration": observed,
            "desired_configuration": desired,
            "missing_settings": missing,
            "evidence_source": "aws_s3api_get_public_access_block",
            "note": (
                "This result verifies the bucket-level S3 Block Public "
                "Access configuration only. It does not establish the "
                "absence of every possible S3 security issue."
            ),
        }

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT_PATH.open("w", encoding="utf-8") as file:
        json.dump(verification, file, indent=2)
        file.write("\n")

    print(f"Verification status: {verification['status']}")
    print(f"Bucket: {bucket['resource_id']}")
    print(f"Checked at: {checked_at}")
    print(f"Output: {OUTPUT_PATH}")

    if verification["status"] == "UNKNOWN":
        print(
            "Review the error or missing settings before drawing conclusions."
        )


if __name__ == "__main__":
    main()
