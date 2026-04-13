import json
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent
FINDINGS_FILE = PROJECT_DIR / "findings" / "securityhub_findings.json"
INVENTORY_FILE = PROJECT_DIR / "inventory" / "inventory.json"
OUTPUT_FILE = PROJECT_DIR / "findings" / "inventory_matches.json"


def load_json(path):
    with path.open(encoding="utf-8") as file:
        return json.load(file)

def normalize_resource_type(resource_type):
    """Map Security Hub resource types to inventory resource types."""
    resource_type_map = {
        "AwsIamRole": "AWS::IAM::Role",
        "AwsAthenaWorkGroup": "AWS::Athena::WorkGroup",
    }

    return resource_type_map.get(resource_type, resource_type)


def canonical_resource_id(resource_type, resource_id):
    """Normalize supported AWS resource identifiers for matching."""
    if not isinstance(resource_id, str):
        return None

    if resource_type == "AWS::S3::Bucket":
        prefix = "arn:aws:s3:::"
        if resource_id.startswith(prefix):
            return resource_id[len(prefix):]

    ec2_arn_markers = {
        "AWS::EC2::VPC": ":vpc/",
        "AWS::EC2::SecurityGroup": ":security-group/",
        "AWS::EC2::Subnet": ":subnet/",
    }

    marker = ec2_arn_markers.get(resource_type)

    if marker and resource_id.startswith("arn:") and marker in resource_id:
        return resource_id.rsplit(marker, 1)[1]

    return resource_id




def main():
    findings_report = load_json(FINDINGS_FILE)
    inventory_report = load_json(INVENTORY_FILE)

    inventory_resources = inventory_report.get("resources", [])

    # Index inventory resources by account, type, and canonical identifier.
    resource_index = {}

    for resource in inventory_resources:

        key = (
            resource.get("account_id"),
            resource.get("region"),
            resource.get("resource_type"),
            canonical_resource_id(
            resource.get("resource_type"),
            resource.get("resource_id"),
            ),
        )
        resource_index.setdefault(key, []).append(resource)

    matched = []
    unmatched = []
    account_level = []
    unsupported_scope = []

    for finding in findings_report.get("findings", []):
        resources = finding.get("resources", [])

        if finding.get("finding_scope") == "account":
            account_level.append({
                "finding_id": finding.get("finding_id"),
                "title": finding.get("title"),
                "severity": finding.get("severity"),
                "workflow_status": finding.get("workflow_status"),
                "account_id": finding.get("account_id"),
                "reason": (
                    "Account-level finding; it is not matched to an "
                    "individual resource."
                ),
            })
            continue

        if finding.get("finding_scope") != "resource":
            unsupported_scope.append({
                "finding_id": finding.get("finding_id"),
                "title": finding.get("title"),
                "finding_scope": finding.get("finding_scope"),
                "reason": "Finding scope could not be classified safely.",
            })
            continue

        # A finding can refer to more than one resource. Evaluate each one.
        for resource in resources:
            account_id = resource.get("account_id") or finding.get("account_id")
            resource_type = normalize_resource_type(
                resource.get("resource_type")
            )
            resource_id = canonical_resource_id(
                resource_type,
                resource.get("resource_id"),
            )


            finding_region = resource.get("region")

            key = (
                account_id,
                finding_region,
                resource_type,
                resource_id,
            )
            candidates = resource_index.get(key, [])

            # IAM is global, but Security Hub can report its findings
            # in a regional context. Fall back to the global IAM entry
            # only when no exact regional match exists.
            if not candidates and resource_type == "AWS::IAM::Role":
                global_key = (
                    account_id,
                    "global",
                    resource_type,
                    resource_id,
                )
                candidates = resource_index.get(global_key, [])

            base = {
                "finding_id": finding.get("finding_id"),
                "title": finding.get("title"),
                "severity": finding.get("severity"),
                "workflow_status": finding.get("workflow_status"),
                "finding_account_id": finding.get("account_id"),
                "resource_type": resource_type,
                "resource_id": resource.get("resource_id"),
                "account_id": account_id,
            }

            if len(candidates) == 1:
                matched.append({
                    **base,
                    "inventory_resource": candidates[0],
                    "match_method": "account_type_resource_id",
                })
            elif len(candidates) > 1:
                unmatched.append({
                    **base,
                    "match_status": "ambiguous",
                    "reason": (
                        "Multiple inventory resources matched the same key."
                    ),
                })
            else:
                unmatched.append({
                    **base,
                    "match_status": "unmatched",
                    "reason": (
                        "No inventory resource matched this account, "
                        "resource type, and identifier."
                    ),
                })

    report = {
        "generated_at": findings_report.get("generated_at"),
        "findings_source": str(FINDINGS_FILE.relative_to(PROJECT_DIR)),
        "inventory_source": str(INVENTORY_FILE.relative_to(PROJECT_DIR)),
        "findings_processed": len(findings_report.get("findings", [])),
        "inventory_resource_count": len(inventory_resources),
        "matched_resource_findings": len(matched),
        "unmatched_resource_entries": len(unmatched),
        "account_level_findings": len(account_level),
        "unclassified_findings": len(unsupported_scope),
        "matched": matched,
        "unmatched": unmatched,
        "account_level": account_level,
        "unclassified": unsupported_scope,
    }

    OUTPUT_FILE.write_text(
        json.dumps(report, indent=2) + "\n",
        encoding="utf-8",
    )

    print(f"Findings processed: {report['findings_processed']}")
    print(f"Inventory resources: {report['inventory_resource_count']}")
    print(f"Matched resource findings: {len(matched)}")
    print(f"Unmatched resource entries: {len(unmatched)}")
    print(f"Account-level findings: {len(account_level)}")
    print(f"Unclassified findings: {len(unsupported_scope)}")
    print(f"Report written to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
