import json
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent

FINDING_PATH = (
    ROOT / "findings" / "fixtures"
    / "synthetic_s3_public_access_finding.json"
)
INVENTORY_PATH = ROOT / "inventory" / "inventory.json"
CATALOG_PATH = (
    ROOT / "remediation" / "catalog"
    / "s3_block_public_access.json"
)
VERIFICATION_PATH = (
    ROOT / "remediation" / "proposals"
    / "s3_live_verification.json"
)
OUTPUT_PATH = ROOT / "remediation" / "proposals"

MAX_VERIFICATION_AGE_SECONDS = 15 * 60


def load_json(path):
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def find_inventory_resource(finding, inventory):
    """Match a finding to a resource using its identifying context."""
    candidates = [
        resource
        for resource in inventory.get("resources", [])
        if resource.get("cloud") == finding.get("cloud")
        and resource.get("account_id") == finding.get("account_id")
        and resource.get("region") == finding.get("region")
        and resource.get("resource_type") == finding.get("resource_type")
        and resource.get("resource_id") == finding.get("resource_id")
    ]

    if len(candidates) != 1:
        raise ValueError(
            "Expected exactly one inventory match; "
            f"found {len(candidates)}."
        )

    return candidates[0]


def validate_inputs(finding, catalog):
    if finding.get("test_fixture") is not True:
        raise ValueError("Expected an explicitly labeled test fixture.")

    if finding.get("fixture_type") != "synthetic":
        raise ValueError("Finding is not labeled synthetic.")

    if finding.get("evidence", {}).get("evidence_status") != "simulated":
        raise ValueError("Synthetic evidence must be labeled simulated.")

    if finding.get("cloud") != catalog.get("cloud_provider"):
        raise ValueError("Finding and catalog cloud providers differ.")

    if finding.get("resource_type") != catalog.get("resource_type"):
        raise ValueError("Finding and catalog resource types differ.")

    title_fragment = catalog["finding_match"]["title_contains"].casefold()
    if title_fragment not in finding.get("title", "").casefold():
        raise ValueError("Finding title does not match the catalog entry.")

    supported = catalog["finding_match"]["severity_supported"]
    if finding.get("severity") not in supported:
        raise ValueError("Finding severity is not supported by the catalog.")


def assess_live_verification(verification, resource):
    """Accept only fresh verification for the exact affected resource."""
    if not isinstance(verification, dict):
        return {
            "status": "UNKNOWN",
            "usable": False,
            "reason": "Verification data is not a JSON object.",
        }

    expected_identity = {
        "cloud": resource.get("cloud"),
        "account_id": resource.get("account_id"),
        "region": resource.get("region"),
        "resource_id": resource.get("resource_id"),
    }

    for field, expected in expected_identity.items():
        if verification.get(field) != expected:
            return {
                "status": "UNKNOWN",
                "usable": False,
                "reason": f"Verification {field} does not match the resource.",
            }

    if verification.get("live_configuration_checked") is not True:
        return {
            "status": "UNKNOWN",
            "usable": False,
            "reason": "Verification does not confirm a live configuration check.",
        }

    try:
        checked_at = datetime.fromisoformat(
            verification["checked_at"].replace("Z", "+00:00")
        )
        if checked_at.tzinfo is None:
            raise ValueError("Timestamp has no timezone.")
        age_seconds = (
            datetime.now(timezone.utc) - checked_at
        ).total_seconds()
    except (KeyError, TypeError, ValueError, AttributeError):
        return {
            "status": "UNKNOWN",
            "usable": False,
            "reason": "Verification timestamp is missing or invalid.",
        }

    if age_seconds < 0:
        return {
            "status": "UNKNOWN",
            "usable": False,
            "reason": "Verification timestamp is in the future.",
        }

    if age_seconds > MAX_VERIFICATION_AGE_SECONDS:
        return {
            "status": "UNKNOWN",
            "usable": False,
            "reason": "Verification is stale; run the verifier again.",
        }

    status = verification.get("status")
    if status not in {"COMPLIANT", "NON_COMPLIANT", "UNKNOWN"}:
        return {
            "status": "UNKNOWN",
            "usable": False,
            "reason": "Verification status is missing or unsupported.",
        }

    return {
        "status": status,
        "usable": status in {"COMPLIANT", "NON_COMPLIANT"},
        "reason": (
            "Fresh live verification for the matched resource."
            if status in {"COMPLIANT", "NON_COMPLIANT"}
            else "The live verifier returned UNKNOWN."
        ),
    }


def decide_remediation(verification_assessment):
    """Make a conservative decision without enabling execution."""
    if not verification_assessment["usable"]:
        return {
            "decision": "HOLD_FOR_REVIEW",
            "reason": verification_assessment["reason"],
        }

    if verification_assessment["status"] == "COMPLIANT":
        return {
            "decision": "NO_ACTION_CURRENT_CONFIGURATION_COMPLIANT",
            "reason": (
                "The latest accepted live verification reports the "
                "desired configuration. The synthetic finding does not "
                "establish that the real resource is vulnerable."
            ),
        }

    return {
        "decision": "REMEDIATION_REVIEW_REQUIRED",
        "reason": (
            "Live verification reports a non-compliant configuration. "
            "Review the evidence, intended access requirements, and "
            "management mechanism before approving any change."
        ),
    }


def build_proposal(finding, resource, catalog, verification):
    remediation = catalog["remediation"]
    risk = catalog["risk_assessment"]

    verification_assessment = assess_live_verification(
        verification, resource
    )
    remediation_decision = decide_remediation(verification_assessment)

    return {
        "proposal_id": f"PROP-{finding['finding_id']}",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "proposal_status": "DRAFT",
        "execution_status": "NOT_EXECUTED",
        "test_fixture": True,
        "evidence_status": "SIMULATED_NOT_LIVE_VERIFIED",
        "warning": (
            "This proposal uses synthetic finding evidence. "
            "The live verification is separate evidence and does not "
            "make the synthetic finding a real finding."
        ),
        "finding": {
            "finding_id": finding["finding_id"],
            "source": finding["source"],
            "title": finding["title"],
            "severity": finding["severity"],
            "workflow_status": finding["workflow_status"],
        },
        "affected_resource": {
            "cloud": resource["cloud"],
            "account_id": resource["account_id"],
            "region": resource["region"],
            "resource_type": resource["resource_type"],
            "resource_id": resource["resource_id"],
            "resource_name": resource.get("resource_name"),
        },
        "evidence": {
            "status": finding["evidence"]["evidence_status"],
            "observed_configuration": (
                finding["evidence"]["observed_configuration"]
            ),
            "inventory_configuration": {
                "management_mechanism": resource.get(
                    "management_mechanism", "unknown"
                ),
                "terraform_management_status": resource.get(
                    "terraform_management_status", "not_assessed"
                ),
            },
            "live_configuration_checked": False,
        },
        "live_verification": {
            "status": (
                verification_assessment["status"]
            ),
            "usable_for_decision": verification_assessment["usable"],
            "reason": verification_assessment["reason"],
            "checked_at": verification.get("checked_at"),
            "evidence_source": verification.get("evidence_source"),
            "observed_configuration": verification.get(
                "observed_configuration"
            ),
        },
        "remediation_decision": remediation_decision,
        "recommended_remediation": {
            "catalog_id": catalog["catalog_id"],
            "summary": remediation["summary"],
            "rationale": remediation["rationale"],
            "desired_configuration": remediation[
                "desired_configuration"
            ],
            "execution_method": remediation["execution_method"],
        },
        "risk_assessment": {
            "risk_level": risk["risk_level"],
            "potential_side_effects": risk["potential_side_effects"],
            "preconditions": risk["preconditions"],
        },
        "governance": {
            "approval_required": True,
            "approval_status": "PENDING",
            "execution_allowed": False,
        },
        "validation": catalog["validation"],
        "rollback": catalog["rollback"],
    }


def main():
    finding = load_json(FINDING_PATH)
    inventory = load_json(INVENTORY_PATH)
    catalog = load_json(CATALOG_PATH)

    validate_inputs(finding, catalog)
    resource = find_inventory_resource(finding, inventory)

    try:
        verification = load_json(VERIFICATION_PATH)
    except (OSError, json.JSONDecodeError):
        verification = {}

    proposal = build_proposal(
        finding, resource, catalog, verification
    )

    # Enforce the safety boundary even if proposal logic changes later.
    proposal["governance"]["execution_allowed"] = False
    proposal["governance"]["approval_required"] = True
    proposal["governance"]["approval_status"] = "PENDING"
    proposal["execution_status"] = "NOT_EXECUTED"

    OUTPUT_PATH.mkdir(parents=True, exist_ok=True)
    output_file = OUTPUT_PATH / "s3_public_access_proposal.json"

    with output_file.open("w", encoding="utf-8") as file:
        json.dump(proposal, file, indent=2)
        file.write("\n")

    print("Proposal generated successfully.")
    print(f"Finding: {finding['finding_id']}")
    print(f"Resource: {resource['resource_id']}")
    print(
        "Live verification: "
        f"{proposal['live_verification']['status']}"
    )
    print(
        "Remediation decision: "
        f"{proposal['remediation_decision']['decision']}"
    )
    print("Approval: PENDING")
    print("Execution: DISABLED")
    print(f"Output: {output_file}")


if __name__ == "__main__":
    main()
