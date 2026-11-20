import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_PATH = (
    PROJECT_ROOT
    / "remediation"
    / "proposals"
    / "s3_logging_destination_discovery.json"
)

REGION = "us-east-1"
ACCOUNT_ID = "665808487090"
SOURCE_BUCKET = "cloud-remediation-mvp-848f82dd"


def run_aws_json(command):
    """Run a read-only AWS CLI command and safely parse its JSON output."""
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        return None, result.stderr.strip() or "AWS CLI request failed."

    if not result.stdout.strip():
        return {}, None

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None, "AWS CLI returned invalid JSON."

    if not isinstance(data, dict):
        return None, "AWS CLI returned an unexpected response structure."

    return data, None


def list_buckets():
    """List buckets visible to the configured AWS identity."""
    return run_aws_json([
        "aws", "s3api", "list-buckets",
        "--region", REGION,
        "--output", "json",
    ])


def get_bucket_location(bucket_name):
    """Return the bucket's AWS region, or an error."""
    data, error = run_aws_json([
        "aws", "s3api", "get-bucket-location",
        "--bucket", bucket_name,
        "--region", REGION,
        "--output", "json",
    ])

    if error:
        return None, error

    location = data.get("LocationConstraint")
    return location or "us-east-1", None


def get_bucket_logging(bucket_name):
    """Inspect logging configuration without changing it."""
    data, error = run_aws_json([
        "aws", "s3api", "get-bucket-logging",
        "--bucket", bucket_name,
        "--region", REGION,
        "--output", "json",
    ])

    if error:
        return None, error

    logging = data.get("LoggingEnabled", {})
    return {
        "enabled": bool(logging),
        "target_bucket": logging.get("TargetBucket"),
        "target_prefix": logging.get("TargetPrefix", ""),
    }, None


def discover():
    checked_at = datetime.now(timezone.utc).isoformat()

    bucket_data, error = list_buckets()
    if error:
        return {
            "checked_at": checked_at,
            "account_id": ACCOUNT_ID,
            "region_scope": REGION,
            "status": "UNKNOWN",
            "error": error,
            "candidates": [],
            "execution_allowed": False,
        }

    buckets = bucket_data.get("Buckets", [])
    candidates = []

    for bucket in buckets:
        name = bucket.get("Name")
        if not name:
            continue

        location, location_error = get_bucket_location(name)
        logging, logging_error = get_bucket_logging(name)

        issues = []

        if name == SOURCE_BUCKET:
            issues.append(
                "Excluded from destination recommendation: "
                "this is the MVP test/source bucket."
            )

        if location_error:
            issues.append("Region could not be verified.")

        elif location != REGION:
            issues.append("Bucket is not in the source bucket's region.")

        if logging_error:
            issues.append("Existing logging configuration could not be verified.")

        candidates.append({
            "bucket_name": name,
            "region": location,
            "region_verified": location_error is None,
            "existing_logging": logging,
            "logging_verified": logging_error is None,
            "issues": issues,
            "candidate_status": "REQUIRES_MANUAL_REVIEW",
            "approved_destination": False,
        })

    return {
        "checked_at": checked_at,
        "account_id": ACCOUNT_ID,
        "source_bucket": SOURCE_BUCKET,
        "region_scope": REGION,
        "status": "DISCOVERY_COMPLETE",
        "bucket_count": len(buckets),
        "candidates": candidates,
        "limitations": [
            "Discovery does not establish destination-bucket suitability.",
            "Bucket permissions, retention, encryption compatibility, and "
            "log-delivery requirements require separate assessment.",
            "No bucket is automatically approved.",
        ],
        "execution_allowed": False,
    }


def main():
    evidence = discover()

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(
        json.dumps(evidence, indent=2) + "\n",
        encoding="utf-8",
    )

    print(f"Discovery status: {evidence['status']}")
    print(f"Evidence file: {OUTPUT_PATH}")

    if evidence.get("error"):
        print(f"Error: {evidence['error']}")
        raise SystemExit(1)

    print(f"Buckets discovered: {evidence['bucket_count']}")
    print("No destination was approved; execution remains disabled.")


if __name__ == "__main__":
    main()
