import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent
TERRAFORM_DIR = PROJECT_DIR / "aws-s3-baseline"
OUTPUT_FILE = Path(__file__).resolve().parent / "inventory.json"


def run_command(args, cwd=None):
    result = subprocess.run(
        args,
        cwd=cwd,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout


def aws_json(*args):
    output = run_command(["aws", *args, "--output", "json"])
    return json.loads(output)


def collect_terraform_buckets():
    state = json.loads(
        run_command(
            ["terraform", "show", "-json"],
            cwd=TERRAFORM_DIR,
        )
    )

    managed = set()

    def walk_module(module):
        for resource in module.get("resources", []):
            if resource.get("type") == "aws_s3_bucket":
                bucket_name = resource.get("values", {}).get("bucket")
                if bucket_name:
                    managed.add(bucket_name)

        for child in module.get("child_modules", []):
            walk_module(child)

    root = state.get("values", {}).get("root_module", {})
    walk_module(root)
    return managed


def get_bucket_region(bucket_name):
    result = aws_json(
        "s3api",
        "get-bucket-location",
        "--bucket",
        bucket_name,
    )
    return result.get("LocationConstraint") or "us-east-1"


def get_bucket_tags(bucket_name):
    try:
        result = aws_json(
            "s3api",
            "get-bucket-tagging",
            "--bucket",
            bucket_name,
        )
        return result.get("TagSet", [])
    except subprocess.CalledProcessError:
        return []


def main():
    identity = aws_json("sts", "get-caller-identity")
    buckets = aws_json("s3api", "list-buckets").get("Buckets", [])
    terraform_buckets = collect_terraform_buckets()

    resources = []

    for bucket in buckets:
        name = bucket["Name"]

        resources.append({
            "cloud": "aws",
            "account_id": identity["Account"],
            "region": get_bucket_region(name),
            "resource_type": "AWS::S3::Bucket",
            "resource_id": name,
            "resource_name": name,
            "tags": get_bucket_tags(name),
            "managed_by_terraform": name in terraform_buckets,
        })

    inventory = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "account_id": identity["Account"],
        "resource_count": len(resources),
        "resources": resources,
    }

    OUTPUT_FILE.write_text(json.dumps(inventory, indent=2) + "\n")

    print(f"Account: {identity['Account']}")
    print(f"S3 buckets discovered: {len(resources)}")
    print(f"Inventory written to: {OUTPUT_FILE}")

    for resource in resources:
        print(
            f"- {resource['resource_name']} | "
            f"{resource['region']} | "
            f"Terraform-managed: {resource['managed_by_terraform']}"
        )


if __name__ == "__main__":
    main()