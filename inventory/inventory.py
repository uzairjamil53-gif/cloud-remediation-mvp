import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent
TERRAFORM_DIR = PROJECT_DIR / "aws-s3-baseline"
OUTPUT_FILE = Path(__file__).resolve().parent / "inventory.json"
AWS_REGION = "us-east-1"

# Terraform resource types that represent primary cloud resources.
TERRAFORM_RESOURCE_TYPE_MAP = {
    "aws_s3_bucket": "AWS::S3::Bucket",
    "aws_vpc": "AWS::EC2::VPC",
    "aws_security_group": "AWS::EC2::SecurityGroup",
    "aws_subnet": "AWS::EC2::Subnet",
    "aws_iam_role": "AWS::IAM::Role",
    "aws_athena_workgroup": "AWS::Athena::WorkGroup",
}


def extract_terraform_resource_identities(state):
    """Extract supported primary-resource identities from Terraform state.

    Returns a dictionary keyed by (inventory resource type, resource ID),
    with each value containing the Terraform resource address.

    Supporting configuration resources, Terraform data sources, and
    unrelated helper resources are intentionally excluded.
    """
    identities = {}

    def walk_module(module):
        for resource in module.get("resources", []):
            if resource.get("mode") != "managed":
                continue

            terraform_type = resource.get("type")
            inventory_type = TERRAFORM_RESOURCE_TYPE_MAP.get(
                terraform_type
            )

            if not inventory_type:
                continue

            values = resource.get("values") or {}

            # Prefer stable cloud identifiers over Terraform-local names.
            if terraform_type == "aws_s3_bucket":
                resource_id = values.get("bucket") or values.get("id")
            elif terraform_type == "aws_iam_role":
                resource_id = values.get("arn") or values.get("id")
            elif terraform_type == "aws_athena_workgroup":
                resource_id = values.get("name") or values.get("id")
            else:
                resource_id = values.get("id")

            address = resource.get("address")

            if resource_id and address:
                identities[(inventory_type, resource_id)] = address

        for child_module in module.get("child_modules", []):
            walk_module(child_module)

    root_module = state.get("values", {}).get("root_module")

    if root_module:
        walk_module(root_module)

    return identities

def apply_terraform_management(resource, terraform_resource_identities):
    """Annotate a resource using identities from the current Terraform state."""
    resource_type = resource["resource_type"]

    # Athena inventory IDs are ARNs, but Terraform state uses workgroup names.
    if resource_type == "AWS::Athena::WorkGroup":
        identity = resource.get("resource_name")
    else:
        identity = resource["resource_id"]

    identity_key = (resource_type, identity)
    terraform_address = terraform_resource_identities.get(identity_key)

    resource["terraform_resource_address"] = terraform_address
    resource["managed_by_terraform"] = (
        True if terraform_address is not None else None
    )
    resource["management_mechanism"] = (
        "terraform" if terraform_address is not None else "unknown"
    )
    resource["terraform_management_status"] = (
        "confirmed_in_current_state"
        if terraform_address is not None
        else "not_found_in_current_state"
    )

    return resource



def run_command(args, cwd=None):
    """Run a command and return its standard output."""
    result = subprocess.run(
        args,
        cwd=cwd,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout


def aws_json(*args):
    """Run an AWS CLI command and parse its JSON output."""
    output = run_command(["aws", *args, "--output", "json"])
    return json.loads(output)


def collect_terraform_resource_identities():
    """Return supported resource identities from the current Terraform state."""
    state = json.loads(
        run_command(
            ["terraform", "show", "-json"],
            cwd=TERRAFORM_DIR,
        )
    )

    return extract_terraform_resource_identities(state)


def get_bucket_region(bucket_name):
    """Return the bucket region."""
    result = aws_json(
        "s3api",
        "get-bucket-location",
        "--bucket",
        bucket_name,
    )
    return result.get("LocationConstraint") or "us-east-1"


def get_bucket_tags(bucket_name):
    """Return bucket tags, or an empty list if tagging is unavailable."""
    try:
        result = aws_json(
            "s3api",
            "get-bucket-tagging",
            "--bucket",
            bucket_name,
        )
        return result.get("TagSet", [])
    except subprocess.CalledProcessError as exc:
        # NoSuchTagSet means the bucket has no tags. Do not silently
        # treat access-denied or unrelated errors as missing tags.
        error_output = f"{exc.stderr or ''}\n{exc.stdout or ''}"
        if "NoSuchTagSet" in error_output:
            return []
        raise


def collect_vpcs(account_id):
    """Discover VPCs in the configured region without modifying them."""
    result = aws_json(
        "ec2",
        "describe-vpcs",
        "--region",
        AWS_REGION,
    )

    resources = []

    for vpc in result.get("Vpcs", []):
        vpc_id = vpc["VpcId"]

        resources.append({
            "cloud": "aws",
            "account_id": account_id,
            "region": AWS_REGION,
            "resource_type": "AWS::EC2::VPC",
            "resource_id": vpc_id,
            "resource_name": vpc_id,
            "arn": (
                f"arn:aws:ec2:{AWS_REGION}:{account_id}:vpc/{vpc_id}"
            ),
            "cidr_block": vpc.get("CidrBlock"),
            "is_default": vpc.get("IsDefault", False),
            "state": vpc.get("State"),
            "tags": vpc.get("Tags", []),
            "management_mechanism": "unknown",
            "terraform_management_status": "not_assessed",
        })

    return resources


def collect_ec2_network_resources(account_id):
    """Discover EC2 security groups and subnets without modifying AWS."""
    resources = []

    security_groups = aws_json(
        "ec2",
        "describe-security-groups",
        "--region",
        AWS_REGION,
    ).get("SecurityGroups", [])

    for group in security_groups:
        group_id = group["GroupId"]

        resources.append({
            "cloud": "aws",
            "account_id": account_id,
            "region": AWS_REGION,
            "resource_type": "AWS::EC2::SecurityGroup",
            "resource_id": group_id,
            "resource_name": group.get("GroupName", group_id),
            "arn": (
                f"arn:aws:ec2:{AWS_REGION}:{account_id}:"
                f"security-group/{group_id}"
            ),
            "vpc_id": group.get("VpcId"),
            "description": group.get("Description"),
            "tags": group.get("Tags", []),
            "management_mechanism": "unknown",
            "terraform_management_status": "not_assessed",
        })

    subnets = aws_json(
        "ec2",
        "describe-subnets",
        "--region",
        AWS_REGION,
    ).get("Subnets", [])

    for subnet in subnets:
        subnet_id = subnet["SubnetId"]

        resources.append({
            "cloud": "aws",
            "account_id": account_id,
            "region": AWS_REGION,
            "resource_type": "AWS::EC2::Subnet",
            "resource_id": subnet_id,
            "resource_name": subnet_id,
            "arn": (
                f"arn:aws:ec2:{AWS_REGION}:{account_id}:"
                f"subnet/{subnet_id}"
            ),
            "vpc_id": subnet.get("VpcId"),
            "cidr_block": subnet.get("CidrBlock"),
            "availability_zone": subnet.get("AvailabilityZone"),
            "state": subnet.get("State"),
            "default_for_az": subnet.get("DefaultForAz"),
            "tags": subnet.get("Tags", []),
            "management_mechanism": "unknown",
            "terraform_management_status": "not_assessed",
        })

    return resources

def collect_iam_roles(account_id):
    """Discover IAM roles without modifying them."""
    result = aws_json(
        "iam",
        "list-roles",
        "--max-items",
        "1000",
    )

    resources = []

    for role in result.get("Roles", []):
        arn = role["Arn"]

        resources.append({
            "cloud": "aws",
            "account_id": account_id,
            "region": "global",
            "resource_type": "AWS::IAM::Role",
            "resource_id": arn,
            "resource_name": role["RoleName"],
            "arn": arn,
            "path": role.get("Path"),
            "created_at": (
                role["CreateDate"].isoformat()
                if hasattr(role.get("CreateDate"), "isoformat")
                else str(role.get("CreateDate"))
                if role.get("CreateDate")
                else None
            ),
            "tags": role.get("Tags", []),
            "management_mechanism": "unknown",
            "terraform_management_status": "not_assessed",
        })

    return resources


def collect_athena_workgroups(account_id):
    """Discover Athena workgroups in the configured region."""
    result = aws_json(
        "athena",
        "list-work-groups",
        "--region",
        AWS_REGION,
    )

    resources = []

    for workgroup in result.get("WorkGroups", []):
        name = workgroup["Name"]
        arn = (
            f"arn:aws:athena:{AWS_REGION}:"
            f"{account_id}:workgroup/{name}"
        )

        resources.append({
            "cloud": "aws",
            "account_id": account_id,
            "region": AWS_REGION,
            "resource_type": "AWS::Athena::WorkGroup",
            "resource_id": arn,
            "resource_name": name,
            "arn": arn,
            "state": workgroup.get("State"),
            "description": workgroup.get("Description"),
            "management_mechanism": "unknown",
            "terraform_management_status": "not_assessed",
        })

    return resources


def collect_vpc_block_public_access(account_id):
    """Inventory account-level VPC Block Public Access settings."""
    result = aws_json(
        "ec2",
        "describe-vpc-block-public-access-options",
        "--region",
        AWS_REGION,
    )

    options = result.get("VpcBlockPublicAccessOptions")

    if not options:
        raise ValueError(
            "AWS returned no VPC Block Public Access options; "
            "configuration status cannot be determined."
        )

    resource_id = (
        f"arn:aws:ec2:{AWS_REGION}:{account_id}:"
        f"vpcblockpublicaccessoptions/{account_id}"
    )

    return [{
        "cloud": "aws",
        "account_id": account_id,
        "region": AWS_REGION,
        "resource_type": "AwsEc2VPCBlockPublicAccessOptions",
        "resource_id": resource_id,
        "resource_name": "VPC Block Public Access account settings",
        "state": options.get("State"),
        "internet_gateway_block_mode": options.get(
            "InternetGatewayBlockMode"
        ),
        "reason": options.get("Reason"),
        "managed_by": options.get("ManagedBy"),
        "exclusions_allowed": options.get("ExclusionsAllowed"),
        "management_mechanism": "aws_account_configuration",
        "terraform_management_status": "not_assessed",
    }]


def collect_snapshot_block_public_access(account_id):
    """Inventory account-level EBS snapshot Block Public Access settings."""
    result = aws_json(
        "ec2",
        "get-snapshot-block-public-access-state",
        "--region",
        AWS_REGION,
    )

    if "State" not in result:
        raise ValueError(
            "AWS returned no EBS snapshot Block Public Access state; "
            "configuration status cannot be determined."
        )

    resource_id = (
        f"arn:aws:ec2:{AWS_REGION}:{account_id}:"
        f"snapshotblockpublicaccess/{account_id}"
    )

    return [{
        "cloud": "aws",
        "account_id": account_id,
        "region": AWS_REGION,
        "resource_type": "AwsEc2SnapshotBlockPublicAccess",
        "resource_id": resource_id,
        "resource_name": "EBS Snapshot Block Public Access account settings",
        "state": result["State"],
        "managed_by": result.get("ManagedBy"),
        "management_mechanism": "aws_account_configuration",
        "terraform_management_status": "not_assessed",
    }]

def collect_s3_buckets(account_id, buckets, terraform_resource_identities):
    """Build inventory records for discovered S3 buckets."""
    resources = []

    for bucket in buckets:
        name = bucket["Name"]
        identity_key = ("AWS::S3::Bucket", name)
        terraform_address = terraform_resource_identities.get(identity_key)
        is_terraform_managed = terraform_address is not None

        resources.append({
            "cloud": "aws",
            "account_id": account_id,
            "region": get_bucket_region(name),
            "resource_type": "AWS::S3::Bucket",
            "resource_id": name,
            "resource_name": name,
            "tags": get_bucket_tags(name),
            "managed_by_terraform": (
                True if is_terraform_managed else None
            ),
            "terraform_resource_address": terraform_address,
            "management_mechanism": (
                "terraform" if is_terraform_managed else "unknown"
            ),
            "terraform_management_status": (
                "confirmed_in_current_state"
                if is_terraform_managed
                else "not_found_in_current_state"
            ),
        })

    return resources


def main():
    identity = aws_json(
        "sts",
        "get-caller-identity",
        "--region",
        AWS_REGION,
    )
    account_id = identity["Account"]

    buckets = aws_json(
        "s3api",
        "list-buckets",
        "--region",
        AWS_REGION,
    ).get("Buckets", [])

    terraform_resource_identities = collect_terraform_resource_identities()


    resources = []

    resources.extend(collect_s3_buckets(
        account_id, buckets, terraform_resource_identities
    ))
    resources.extend(collect_vpcs(account_id))
    resources.extend(collect_ec2_network_resources(account_id))
    resources.extend(collect_iam_roles(account_id))
    resources.extend(collect_athena_workgroups(account_id))
    resources.extend(collect_vpc_block_public_access(account_id))
    resources.extend(collect_snapshot_block_public_access(account_id))

    # Classify supported primary resources using the current Terraform state.
    terraform_supported_types = set(
        TERRAFORM_RESOURCE_TYPE_MAP.values()
    )

    for resource in resources:
        if resource["resource_type"] in terraform_supported_types:
            apply_terraform_management(
                resource,
                terraform_resource_identities,
            )

    inventory = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "cloud_provider": "aws",
        "account_id": account_id,
        "region_scope": [AWS_REGION],
        "resource_count": len(resources),
        "resource_counts_by_type": {},
        "resources": resources,
    }

    counts = {}
    for resource in resources:
        resource_type = resource["resource_type"]
        counts[resource_type] = counts.get(resource_type, 0) + 1

    inventory["resource_counts_by_type"] = counts

    management_counts = {}

    for resource in resources:
        mechanism = resource.get("management_mechanism", "unknown")
        management_counts[mechanism] = (
            management_counts.get(mechanism, 0) + 1
        )

    inventory["management_counts"] = management_counts

    OUTPUT_FILE.write_text(
        json.dumps(inventory, indent=2) + "\n",
        encoding="utf-8",
    )

    s3_count = counts.get("AWS::S3::Bucket", 0)

    print(f"Account: {account_id}")
    print(f"Region: {AWS_REGION}")
    print(f"S3 buckets discovered: {s3_count}")
    print(f"Total resources inventoried: {len(resources)}")
    print(f"Inventory written to: {OUTPUT_FILE}")

    print("\nManagement classification summary:")

    for mechanism, count in sorted(management_counts.items()):
        print(f"- {mechanism}: {count}")

    for resource in resources:
        management = resource.get("management_mechanism", "unknown")

        if resource["resource_type"] == "AWS::S3::Bucket":
            management = (
                f"Terraform-managed: {resource['managed_by_terraform']}"
            )

        print(
            f"- {resource['resource_type']} | "
            f"{resource['resource_name']} | "
            f"{resource['region']} | "
            f"Management: {management}"
        )


if __name__ == "__main__":
    main()
