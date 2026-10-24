import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

PROJECT_ROOT = Path(__file__).resolve().parent.parent

FINDINGS_PATH = PROJECT_ROOT / "findings" / "securityhub_findings.json"
INVENTORY_PATH = PROJECT_ROOT / "inventory" / "inventory.json"

CATALOG_PATH = (
    PROJECT_ROOT
    / "remediation"
    / "catalog"
    / "ec2_default_security_group_closed.json"
)

VERIFICATION_PATH = (
    PROJECT_ROOT
    / "remediation"
    / "proposals"
    / "ec2_default_security_group_verification.json"
)

OUTPUT_PATH = (
    PROJECT_ROOT
    / "remediation"
    / "proposals"
    / "ec2_default_security_group_proposal.json"
)

MAX_EVIDENCE_AGE_SECONDS = 900

EXPECTED_ACCOUNT_ID = "665808487090"
EXPECTED_REGION = "us-east-1"
EXPECTED_CONTROL_ID = "EC2.2"
EXPECTED_SECURITY_GROUP_ID = "sg-02feb1c261f4555ab"
EXPECTED_VPC_ID = "vpc-0ccb1ae9029082eba"

EXPECTED_RESOURCE_ARN = (
    "arn:aws:ec2:us-east-1:665808487090:"
    "security-group/sg-02feb1c261f4555ab"
)

EXPECTED_FINDING_ID = (
    "arn:aws:securityhub:us-east-1:665808487090:"
    "security-control/EC2.2/finding/"
    "4e15ead1-0009-48f6-9cde-fc9eedf1b46e"
)


def load_json(path):
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def parse_timestamp(value):
    if not isinstance(value, str):
        raise ValueError("Timestamp must be a string.")

    timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))

    if timestamp.tzinfo is None:
        raise ValueError("Timestamp must include a timezone.")

    return timestamp.astimezone(timezone.utc)


def find_real_finding(findings, catalog):
    candidates = []

    match = catalog["finding_match"]
    title_contains = match["title_contains"].lower()
    severities = match["severities"]

    for finding in findings.get("findings", []):
        if finding.get("security_control_id") != EXPECTED_CONTROL_ID:
            continue

        if finding.get("finding_id") != EXPECTED_FINDING_ID:
            continue

        if title_contains not in finding.get("title", "").lower():
            continue

        if finding.get("severity") not in severities:
            continue

        candidates.append(finding)

    if len(candidates) != 1:
        raise ValueError(
            "Expected exactly one stored EC2.2 finding matching the "
            f"catalog and expected ID; found {len(candidates)}. "
            "Refusing to guess."
        )

    return candidates[0]


def find_inventory_resource(inventory):
    candidates = []

    for resource in inventory.get("resources", []):
        if resource.get("cloud") != "aws":
            continue

        if resource.get("account_id") != EXPECTED_ACCOUNT_ID:
            continue

        if resource.get("region") != EXPECTED_REGION:
            continue

        if resource.get("resource_type") != "AWS::EC2::SecurityGroup":
            continue

        if resource.get("resource_id") != EXPECTED_SECURITY_GROUP_ID:
            continue

        if resource.get("arn") != EXPECTED_RESOURCE_ARN:
            continue

        if resource.get("vpc_id") != EXPECTED_VPC_ID:
            continue

        candidates.append(resource)

    if len(candidates) != 1:
        raise ValueError(
            "Expected exactly one inventory match for the security group; "
            f"found {len(candidates)}. Refusing to guess."
        )

    return candidates[0]


def validate_finding_resource(finding):
    resources = finding.get("resources")

    if not isinstance(resources, list):
        raise ValueError("Finding resources field is not a list.")

    candidates = [
        resource
        for resource in resources
        if isinstance(resource, dict)
        and resource.get("resource_scope") == "resource"
        and resource.get("resource_type") == "AWS::EC2::SecurityGroup"
        and resource.get("resource_id") == EXPECTED_RESOURCE_ARN
        and resource.get("arn") == EXPECTED_RESOURCE_ARN
        and resource.get("account_id") == EXPECTED_ACCOUNT_ID
        and resource.get("region") == EXPECTED_REGION
    ]

    if len(candidates) != 1:
        raise ValueError(
            "Finding does not contain exactly one matching security group "
            f"resource; found {len(candidates)}."
        )


def validate_verification(verification, finding, inventory_resource):
    reasons = []
    age_seconds = None

    try:
        checked_at = parse_timestamp(verification.get("checked_at"))
        age_seconds = (
            datetime.now(timezone.utc) - checked_at
        ).total_seconds()
    except (TypeError, ValueError):
        reasons.append("Verification timestamp is missing or invalid.")

    if age_seconds is not None:
        if age_seconds < -60:
            reasons.append("Verification timestamp is unexpectedly in the future.")
        elif age_seconds > MAX_EVIDENCE_AGE_SECONDS:
            reasons.append("Live verification evidence is stale.")

    if (
        verification.get("verification_type")
        != "live_ec2_default_security_group_configuration"
    ):
        reasons.append("Verification type does not match EC2.2.")

    if verification.get("read_only") is not True:
        reasons.append("Verification is not explicitly marked read-only.")

    if verification.get("execution_allowed") is not False:
        reasons.append("Verification does not explicitly disable execution.")

    if verification.get("error") is not None:
        reasons.append("Live verification contains an error.")

    verified_finding = verification.get("finding", {})

    if verified_finding.get("finding_id") != finding.get("finding_id"):
        reasons.append("Verification finding ID does not match.")

    if verified_finding.get("security_control_id") != EXPECTED_CONTROL_ID:
        reasons.append("Verification security control ID does not match.")

    if verified_finding.get("compliance_status") != "FAILED":
        reasons.append("Verification finding is not confirmed FAILED.")

    if verified_finding.get("record_state") != "ACTIVE":
        reasons.append("Verification finding is not confirmed ACTIVE.")

    verified_resource = verification.get("resource", {})

    if verified_resource.get("resource_id") != EXPECTED_RESOURCE_ARN:
        reasons.append("Verification resource ARN does not match.")

    if verified_resource.get("security_group_id") != EXPECTED_SECURITY_GROUP_ID:
        reasons.append("Verification security group ID does not match.")

    if verified_resource.get("account_id") != EXPECTED_ACCOUNT_ID:
        reasons.append("Verification account ID does not match.")

    if verified_resource.get("region") != EXPECTED_REGION:
        reasons.append("Verification region does not match.")

    if verified_resource.get("resource_type") != "AWS::EC2::SecurityGroup":
        reasons.append("Verification resource type does not match.")

    if verified_resource.get("vpc_id") != EXPECTED_VPC_ID:
        reasons.append("Verification VPC ID does not match.")

    if verified_resource.get("resource_id") != inventory_resource.get("arn"):
        reasons.append("Verification resource ARN does not match inventory.")

    live_configuration = verification.get("live_configuration", {})

    status = verification.get("status")

    if status == "NON_COMPLIANT":
        if live_configuration.get("inbound_rules_empty") is not False:
            reasons.append(
                "NON_COMPLIANT status lacks evidence of inbound rules."
            )

        if live_configuration.get("outbound_rules_empty") is not False:
            reasons.append(
                "NON_COMPLIANT status lacks evidence of outbound rules."
            )

        if live_configuration.get("inbound_rule_count", 0) <= 0:
            reasons.append("Inbound rule count is not positive.")

        if live_configuration.get("outbound_rule_count", 0) <= 0:
            reasons.append("Outbound rule count is not positive.")

    elif status == "COMPLIANT":
        if live_configuration.get("inbound_rules_empty") is not True:
            reasons.append(
                "COMPLIANT status lacks evidence of empty inbound rules."
            )

        if live_configuration.get("outbound_rules_empty") is not True:
            reasons.append(
                "COMPLIANT status lacks evidence of empty outbound rules."
            )

    else:
        reasons.append("Live verification status is unknown or unsupported.")

    return not reasons, reasons, age_seconds


def build_proposal(findings, inventory, catalog, verification):
    finding = find_real_finding(findings, catalog)

    if finding.get("cloud_provider") != "aws":
        raise ValueError("Finding cloud provider is not AWS.")

    if finding.get("account_id") != EXPECTED_ACCOUNT_ID:
        raise ValueError("Finding account ID does not match expected account.")

    if finding.get("region") != EXPECTED_REGION:
        raise ValueError("Finding region does not match expected region.")

    validate_finding_resource(finding)

    inventory_resource = find_inventory_resource(inventory)

    usable, verification_reasons, age_seconds = validate_verification(
        verification,
        finding,
        inventory_resource,
    )

    live_status = verification.get("status", "UNKNOWN")

    if not usable:
        decision = "HOLD_FOR_REVIEW"
        decision_reason = (
            "Live evidence could not be accepted. Resolve evidence issues "
            "before deciding on remediation."
        )
    elif live_status == "COMPLIANT":
        decision = "NO_ACTION_CURRENT_CONFIGURATION_COMPLIANT"
        decision_reason = (
            "Accepted live verification reports that the default security "
            "group has no inbound or outbound rules. Review the original "
            "finding and evidence before closure."
        )
    else:
        decision = "REMEDIATION_REVIEW_REQUIRED"
        decision_reason = (
            "Accepted live verification confirms that the default security "
            "group has inbound and outbound rules. Removing them requires "
            "dependency analysis, impact review, and explicit approval."
        )

    remediation = catalog["remediation"]
    risk = catalog["risk"]
    governance = catalog["governance"]

    management_mechanism = inventory_resource.get(
        "management_mechanism", "unknown"
    )

    unresolved_prerequisites = list(catalog.get("preconditions", []))

    if (
        not isinstance(management_mechanism, str)
        or not management_mechanism.strip()
        or management_mechanism.strip().lower() == "unknown"
    ):
        unresolved_prerequisites.append(
            "Management mechanism is unknown; identify and verify it."
        )

    unresolved_prerequisites.extend([
        "Confirm the security group has no workload dependencies.",
        "Review the exact connectivity impact before removing rules.",
        "Confirm the approved management workflow and change process.",
    ])

    proposal_status = (
        "REVIEW_REQUIRED"
        if decision == "NO_ACTION_CURRENT_CONFIGURATION_COMPLIANT"
        else "DRAFT"
    )

    proposal = {
        "proposal_id": (
            f"PROP-AWS-EC2-DEFAULT-SG-{uuid4().hex[:12].upper()}"
        ),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "proposal_status": proposal_status,
        "execution_status": "NOT_EXECUTED",
        "test_fixture": False,
        "evidence_status": (
            "LIVE_VERIFIED" if usable else "LIVE_EVIDENCE_REJECTED"
        ),
        "warning": (
            "This proposal uses a real Security Hub finding. It is not "
            "authorization to modify AWS resources."
        ),
        "finding": {
            "finding_id": finding.get("finding_id"),
            "source": finding.get("source_provider"),
            "title": finding.get("title"),
            "severity": finding.get("severity"),
            "workflow_status": finding.get("workflow_status"),
            "compliance_status": finding.get("compliance_status"),
            "security_control_id": finding.get("security_control_id"),
        },
        "affected_resource": {
            "cloud": finding.get("cloud_provider"),
            "account_id": finding.get("account_id"),
            "region": finding.get("region"),
            "resource_type": inventory_resource.get("resource_type"),
            "resource_id": inventory_resource.get("arn"),
            "resource_name": inventory_resource.get("resource_name"),
            "security_group_id": inventory_resource.get("resource_id"),
            "vpc_id": inventory_resource.get("vpc_id"),
        },
        "evidence": {
            "status": "live" if usable else "rejected",
            "live_configuration_checked": True,
            "evidence_source": verification.get("evidence_source"),
            "inbound_rule_count": verification.get(
                "live_configuration", {}
            ).get("inbound_rule_count"),
            "outbound_rule_count": verification.get(
                "live_configuration", {}
            ).get("outbound_rule_count"),
            "inbound_rules_empty": verification.get(
                "live_configuration", {}
            ).get("inbound_rules_empty"),
            "outbound_rules_empty": verification.get(
                "live_configuration", {}
            ).get("outbound_rules_empty"),
            "verification_age_seconds": (
                round(age_seconds, 2) if age_seconds is not None else None
            ),
            "verification_issues": verification_reasons,
        },
        "live_verification": {
            "status": live_status,
            "usable_for_decision": usable,
            "checked_at": verification.get("checked_at"),
            "evidence_source": verification.get("evidence_source"),
        },
        "remediation_decision": {
            "decision": decision,
            "reason": decision_reason,
        },
        "recommended_remediation": {
            "catalog_id": catalog["catalog_id"],
            "summary": remediation["summary"],
            "desired_configuration": remediation["desired_configuration"],
            "execution_method": remediation["execution_method"],
            "execution_status": remediation["execution_status"],
        },
        "management_context": {
            "management_mechanism": management_mechanism,
            "terraform_management_status": inventory_resource.get(
                "terraform_management_status"
            ),
            "terraform_resource_address": inventory_resource.get(
                "terraform_resource_address"
            ),
            "managed_by_terraform": inventory_resource.get(
                "managed_by_terraform"
            ),
            "note": (
                "Management metadata is inventory evidence, not permission "
                "to change the resource. Any change must use the confirmed "
                "management workflow and avoid unmanaged drift."
            ),
        },
        "risk_assessment": {
            "risk_level": risk["level"],
            "potential_side_effects": risk["potential_side_effects"],
            "preconditions": catalog.get("preconditions", []),
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

    # Enforce the safety boundary regardless of catalog or decision changes.
    proposal["governance"]["approval_required"] = True
    proposal["governance"]["approval_status"] = "PENDING"
    proposal["governance"]["execution_allowed"] = False
    proposal["execution_status"] = "NOT_EXECUTED"

    return proposal


def main():
    findings = load_json(FINDINGS_PATH)
    inventory = load_json(INVENTORY_PATH)
    catalog = load_json(CATALOG_PATH)
    verification = load_json(VERIFICATION_PATH)

    proposal = build_proposal(
        findings,
        inventory,
        catalog,
        verification,
    )

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    OUTPUT_PATH.write_text(
        json.dumps(proposal, indent=2) + "\n",
        encoding="utf-8",
    )

    print("EC2.2 proposal generated.")
    print(f"Proposal ID: {proposal['proposal_id']}")
    print(f"Finding: {proposal['finding']['finding_id']}")
    print(f"Resource: {proposal['affected_resource']['security_group_id']}")
    print(f"Live verification: {proposal['live_verification']['status']}")
    print(f"Evidence status: {proposal['evidence_status']}")
    print(f"Decision: {proposal['remediation_decision']['decision']}")
    print(f"Proposal status: {proposal['proposal_status']}")
    print("Approval: PENDING")
    print("Execution: DISABLED")
    print(f"Output: {OUTPUT_PATH}")


if __name__ == "__main__":
    main()