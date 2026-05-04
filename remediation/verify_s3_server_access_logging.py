import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

FINDINGS_PATH = PROJECT_ROOT / "findings" / "securityhub_findings.json"
INVENTORY_PATH = PROJECT_ROOT / "inventory" / "inventory.json"
CATALOG_PATH = (
    PROJECT_ROOT / "remediation" / "catalog" / "s3_server_access_logging.json"
)
OUTPUT_PATH = (
    PROJECT_ROOT
    / "remediation"
    / "proposals"
    / "s3_server_access_logging_verification.json"
)

REGION = "us-east-1"
ACCOUNT_ID = "665808487090"


def load_json(path):
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def get_records(data):
    """Support common list and dictionary wrappers in project JSON files."""
    if isinstance(data, list):
        return data

    if isinstance(data, dict):
        for key in ("findings", "resources", "inventory"):
            value = data.get(key)
            if isinstance(value, list):
                return value

    raise ValueError("Could not identify a record list in the JSON input.")


def find_s3_9_finding(findings, catalog):
    match = catalog["finding_match"]
    candidates = []

    for finding in get_records(findings):
        if finding.get("security_control_id") != match["security_control_id"]:
            continue

        if match["title_contains"].lower() not in finding.get("title", "").lower():
            continue

        if finding.get("cloud_provider") != "aws":
            continue

        if finding.get("account_id") != ACCOUNT_ID:
            continue

        if finding.get("region") != REGION:
            continue

        if finding.get("finding_scope") != "resource":
            continue

        if finding.get("severity") not in match["severity_supported"]:
            continue

        if finding.get("record_state") not in (None, "ACTIVE"):
            continue

        if finding.get("workflow_status") in ("RESOLVED", "SUPPRESSED"):
            continue

        for resource in finding.get("resources", []):
            if resource.get("resource_type") != catalog["resource_type"]:
                continue

            candidates.append((finding, resource))

    if len(candidates) != 1:
        raise ValueError(
            "Expected exactly one matching active S3.9 resource finding; "
            f"found {len(candidates)}. Refusing to guess."
        )

    return candidates[0]


def extract_bucket_name(resource):
    resource_id = resource.get("resource_id", "")

    prefix = "arn:aws:s3:::"
    if resource_id.startswith(prefix):
        bucket_name = resource_id[len(prefix):]
    else:
        bucket_name = resource_id

    if not bucket_name or "/" in bucket_name:
        raise ValueError(
            f"Cannot safely resolve S3 bucket name from resource ID: {resource_id}"
        )

    return bucket_name


def find_inventory_resource(inventory, bucket_name, catalog):
    candidates = []

    for resource in get_records(inventory):
        if resource.get("cloud") != "aws":
            continue

        if resource.get("resource_type") != catalog["resource_type"]:
            continue

        resource_id = resource.get("resource_id", "")
        resource_name = resource.get("resource_name", resource.get("name", ""))

        if bucket_name in (resource_id, resource_name):
            candidates.append(resource)

    if len(candidates) != 1:
        raise ValueError(
            "Expected exactly one inventory match for bucket "
            f"{bucket_name}; found {len(candidates)}. Refusing to guess."
        )

    return candidates[0]


def read_logging_configuration(bucket_name):
    command = [
        "aws",
        "s3api",
        "get-bucket-logging",
        "--bucket",
        bucket_name,
        "--region",
        REGION,
        "--output",
        "json",
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        message = result.stderr.strip() or "AWS CLI request failed."
        return None, message

    # AWS CLI may emit no JSON when the bucket has no active logging config.
    if not result.stdout.strip():
        return {}, None

    try:
        configuration = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None, "AWS CLI returned output that was not valid JSON."

    if not isinstance(configuration, dict):
        return None, "AWS CLI returned an unexpected response structure."

    return configuration, None


def main():
    findings = load_json(FINDINGS_PATH)
    inventory = load_json(INVENTORY_PATH)
    catalog = load_json(CATALOG_PATH)

    finding, resource = find_s3_9_finding(findings, catalog)
    bucket_name = extract_bucket_name(resource)
    inventory_resource = find_inventory_resource(
        inventory, bucket_name, catalog
    )

    configuration, error = read_logging_configuration(bucket_name)

    if error:
        status = "UNKNOWN"
        logging_enabled = None
        target_bucket = None
        target_prefix = None
    else:
        logging = configuration.get("LoggingEnabled", {})
        logging_enabled = bool(logging)
        target_bucket = logging.get("TargetBucket")
        target_prefix = logging.get("TargetPrefix", "")

        status = "COMPLIANT" if logging_enabled else "NON_COMPLIANT"

    evidence = {
        "verification_type": "live_s3_server_access_logging",
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "status": status,
        "finding": {
            "finding_id": finding.get("finding_id"),
            "title": finding.get("title"),
            "security_control_id": finding.get("security_control_id"),
            "severity": finding.get("severity"),
            "workflow_status": finding.get("workflow_status"),
        },
        "resource": {
            "bucket_name": bucket_name,
            "resource_id": resource.get("resource_id"),
            "resource_type": resource.get("resource_type"),
            "region": REGION,
            "account_id": ACCOUNT_ID,
        },
        "inventory": {
            "management_mechanism": inventory_resource.get(
                "management_mechanism"
            ),
            "terraform_management_status": inventory_resource.get(
                "terraform_management_status"
            ),
        },
        "live_configuration": {
            "logging_enabled": logging_enabled,
            "target_bucket": target_bucket,
            "target_prefix": target_prefix,
        },
        "evidence_source": "aws s3api get-bucket-logging",
        "read_only": True,
        "execution_allowed": False,
        "error": error,
        "limitations": [
            "This verifies the source bucket's logging configuration only.",
            "It does not verify destination bucket permissions, region, retention, "
            "or successful log delivery.",
            "No remediation was executed.",
        ],
    }

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(
        json.dumps(evidence, indent=2) + "\n",
        encoding="utf-8",
    )

    print(f"Finding: {finding.get('title')}")
    print(f"Bucket: {bucket_name}")
    print(f"Management mechanism: "
          f"{inventory_resource.get('management_mechanism')}")
    print(f"Verification status: {status}")

    if error:
        print(f"Error: {error}")
    elif status == "COMPLIANT":
        print(f"Logging destination: {target_bucket}")
        print(f"Target prefix: {target_prefix}")

    print(f"Evidence written to: {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
