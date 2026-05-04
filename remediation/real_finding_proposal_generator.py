import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

PROJECT_ROOT = Path(__file__).resolve().parent.parent

FINDINGS_PATH = PROJECT_ROOT / "findings" / "securityhub_findings.json"
INVENTORY_PATH = PROJECT_ROOT / "inventory" / "inventory.json"
CATALOG_PATH = (
    PROJECT_ROOT / "remediation" / "catalog" / "s3_server_access_logging.json"
)
VERIFICATION_PATH = (
    PROJECT_ROOT
    / "remediation"
    / "proposals"
    / "s3_server_access_logging_verification.json"
)
OUTPUT_PATH = (
    PROJECT_ROOT
    / "remediation"
    / "proposals"
    / "s3_server_access_logging_proposal.json"
)

DESTINATION_DISCOVERY_PATH = (
    PROJECT_ROOT
    / "remediation"
    / "proposals"
    / "s3_logging_destination_discovery.json"
)

MAX_EVIDENCE_AGE_SECONDS = 900


def load_json(path):
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def load_destination_discovery():
    """Load and validate destination discovery evidence without approving a bucket."""
    if not DESTINATION_DISCOVERY_PATH.exists():
        return {
            "status": "UNAVAILABLE",
            "reason": "Destination discovery evidence file is missing.",
            "candidate_count": 0,
            "approved_candidates": [],
        }

    try:
        data = load_json(DESTINATION_DISCOVERY_PATH)
    except (OSError, json.JSONDecodeError):
        return {
            "status": "INVALID",
            "reason": "Destination discovery evidence could not be read.",
            "candidate_count": 0,
            "approved_candidates": [],
        }

    if not isinstance(data, dict):
        return {
            "status": "INVALID",
            "reason": "Destination discovery evidence must be a JSON object.",
            "candidate_count": 0,
            "approved_candidates": [],
        }

    checked_at = data.get("checked_at")
    try:
        timestamp = datetime.fromisoformat(
            checked_at.replace("Z", "+00:00")
        )
        if timestamp.tzinfo is None:
            raise ValueError("Timestamp must include a timezone.")

        age_seconds = (
            datetime.now(timezone.utc)
            - timestamp.astimezone(timezone.utc)
        ).total_seconds()
    except (AttributeError, TypeError, ValueError):
        return {
            "status": "INVALID",
            "reason": "Destination discovery timestamp is missing or invalid.",
            "candidate_count": 0,
            "approved_candidates": [],
        }

    if age_seconds < 0 or age_seconds > MAX_EVIDENCE_AGE_SECONDS:
        return {
            "status": "STALE",
            "reason": (
                "Destination discovery evidence is outside the "
                "15-minute freshness window."
            ),
            "candidate_count": 0,
            "approved_candidates": [],
        }

    if (
        data.get("status") != "DISCOVERY_COMPLETE"
        or data.get("execution_allowed") is not False
        or data.get("account_id") != "665808487090"
        or data.get("region_scope") != "us-east-1"
        or not isinstance(data.get("candidates"), list)
    ):
        return {
            "status": "INVALID",
            "reason": (
                "Destination discovery evidence has an unexpected "
                "status, scope, or structure."
            ),
            "candidate_count": 0,
            "approved_candidates": [],
        }

    candidates = data["candidates"]

    approved_candidates = [
        candidate
        for candidate in candidates
        if isinstance(candidate, dict)
        and candidate.get("approved_destination") is True
        and isinstance(candidate.get("bucket_name"), str)
        and bool(candidate["bucket_name"])
        and candidate.get("region") == "us-east-1"
        and candidate.get("region_verified") is True
        and candidate.get("logging_verified") is True
        and candidate.get("candidate_status") == "APPROVED"
        and not candidate.get("issues")
        and candidate["bucket_name"] != data.get("source_bucket")
    ]

    return {
        "status": "VALID",
        "reason": (
            "Discovery evidence is fresh. Destination suitability "
            "and approval must still be independently reviewed."
        ),
        "candidate_count": len(candidates),
        "approved_candidates": approved_candidates,
    }



def records_from(data, key):
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and isinstance(data.get(key), list):
        return data[key]
    raise ValueError(f"Expected a list or a dictionary containing '{key}'.")


def find_real_finding(findings, catalog):
    finding_records = records_from(findings, "findings")
    criteria = catalog["finding_match"]
    candidates = []

    for finding in finding_records:
        if finding.get("security_control_id") != criteria["security_control_id"]:
            continue

        if criteria["title_contains"].lower() not in finding.get("title", "").lower():
            continue

        if finding.get("cloud_provider") != catalog["cloud_provider"]:
            continue

        if finding.get("finding_scope") != "resource":
            continue

        if finding.get("severity") not in criteria["severity_supported"]:
            continue

        if finding.get("record_state") != "ACTIVE":
            continue

        if finding.get("workflow_status") in ("RESOLVED", "SUPPRESSED"):
            continue

        for resource in finding.get("resources", []):
            if resource.get("resource_type") == catalog["resource_type"]:
                candidates.append((finding, resource))

    if len(candidates) != 1:
        raise ValueError(
            "Expected exactly one active real finding matching the catalog; "
            f"found {len(candidates)}. Refusing to guess."
        )

    return candidates[0]


def bucket_name_from_resource(resource):
    resource_id = resource.get("resource_id", "")
    prefix = "arn:aws:s3:::"

    if resource_id.startswith(prefix):
        bucket_name = resource_id[len(prefix):]
    else:
        bucket_name = resource_id

    if not bucket_name or "/" in bucket_name:
        raise ValueError("Could not safely identify the S3 bucket.")

    return bucket_name


def find_inventory_resource(inventory, bucket_name, finding, catalog):
    candidates = []

    for resource in records_from(inventory, "resources"):
        if resource.get("cloud") != finding.get("cloud_provider"):
            continue

        if resource.get("account_id") != finding.get("account_id"):
            continue

        if resource.get("resource_type") != catalog["resource_type"]:
            continue

        if resource.get("region") != finding.get("region"):
            continue

        if bucket_name not in (
            resource.get("resource_id"),
            resource.get("resource_name"),
        ):
            continue

        candidates.append(resource)

    if len(candidates) != 1:
        raise ValueError(
            "Expected exactly one inventory match for the finding's resource; "
            f"found {len(candidates)}. Refusing to guess."
        )

    return candidates[0]


def validate_verification(verification, finding, resource, bucket_name):
    reasons = []
    checked_at = verification.get("checked_at")

    try:
        checked_time = datetime.fromisoformat(checked_at)
        if checked_time.tzinfo is None:
            raise ValueError("Timestamp must include a timezone.")
        age_seconds = (
            datetime.now(timezone.utc) - checked_time.astimezone(timezone.utc)
        ).total_seconds()
    except (TypeError, ValueError):
        age_seconds = None
        reasons.append("Verification timestamp is missing or invalid.")

    if age_seconds is not None:
        if age_seconds < -60:
            reasons.append("Verification timestamp is unexpectedly in the future.")
        elif age_seconds > MAX_EVIDENCE_AGE_SECONDS:
            reasons.append("Live verification evidence is stale.")

    if verification.get("verification_type") != "live_s3_server_access_logging":
        reasons.append("Verification type does not match the catalog.")

    if verification.get("read_only") is not True:
        reasons.append("Verification is not explicitly marked read-only.")

    if verification.get("execution_allowed") is not False:
        reasons.append("Verification does not explicitly disable execution.")

    verified_finding = verification.get("finding", {})
    if verified_finding.get("finding_id") != finding.get("finding_id"):
        reasons.append("Verification finding ID does not match.")

    verified_resource = verification.get("resource", {})
    if verified_resource.get("bucket_name") != bucket_name:
        reasons.append("Verification bucket name does not match.")

    if verified_resource.get("resource_id") != resource.get("resource_id"):
        reasons.append("Verification resource ID does not match.")

    if verified_resource.get("account_id") != finding.get("account_id"):
        reasons.append("Verification account does not match.")

    if verified_resource.get("region") != finding.get("region"):
        reasons.append("Verification region does not match.")

    if verified_resource.get("resource_type") != resource.get("resource_type"):
        reasons.append("Verification resource type does not match.")

    if verification.get("error") is not None:
        reasons.append("Live verification contains an error.")

    status = verification.get("status")
    live_config = verification.get("live_configuration", {})
    if status == "NON_COMPLIANT" and live_config.get("logging_enabled") is not False:
        reasons.append("Non-compliant status lacks matching disabled-logging evidence.")
    elif status == "COMPLIANT" and live_config.get("logging_enabled") is not True:
        reasons.append("Compliant status lacks matching enabled-logging evidence.")
    elif status not in ("COMPLIANT", "NON_COMPLIANT"):
        reasons.append("Live verification status is unknown or unsupported.")

    return not reasons, reasons, age_seconds

def assess_management_compatibility(inventory_resource, remediation):
    """Assess whether the catalog execution method matches inventory evidence."""
    mechanism = inventory_resource.get("management_mechanism")
    terraform_status = inventory_resource.get("terraform_management_status")
    execution_method = remediation.get("execution_method")

    result = {
        "execution_method": execution_method,
        "management_mechanism": mechanism,
        "terraform_management_status": terraform_status,
        "compatible": None,
        "status": "UNKNOWN",
        "reason": "",
        "unresolved_prerequisites": [],
    }

    if not isinstance(mechanism, str) or not mechanism.strip():
        result["reason"] = (
            "The inventory does not identify the resource's management mechanism."
        )
        result["unresolved_prerequisites"].append(
            "Identify and verify the resource's management mechanism."
        )
        return result

    mechanism = mechanism.strip().lower()
    result["management_mechanism"] = mechanism

    if mechanism == "unknown":
        result["reason"] = (
            "The inventory explicitly marks the management mechanism as unknown."
        )
        result["unresolved_prerequisites"].append(
            "Identify and verify the resource's management mechanism."
        )
        return result

    if execution_method == "requires_approved_management_mechanism":
        result["status"] = "MECHANISM_IDENTIFIED_APPROVAL_REQUIRED"
        result["reason"] = (
            "A management mechanism is identified, but its approved change "
            "workflow must still be confirmed."
        )
        result["unresolved_prerequisites"].append(
            "Confirm the approved management workflow and change process."
        )
        return result

    if execution_method == "terraform":
        if mechanism != "terraform":
            result["status"] = "INCOMPATIBLE"
            result["compatible"] = False
            result["reason"] = (
                "The catalog requires Terraform, but the inventory identifies "
                f"the management mechanism as '{mechanism}'."
            )
            result["unresolved_prerequisites"].append(
                "Resolve the management-mechanism mismatch before planning "
                "or executing remediation."
            )
            return result

        if terraform_status != "confirmed_in_current_state":
            result["status"] = "UNVERIFIED"
            result["reason"] = (
                "The inventory identifies Terraform, but current Terraform "
                "state membership is not confirmed."
            )
            result["unresolved_prerequisites"].append(
                "Verify that the resource is managed by the current Terraform "
                "state before planning changes."
            )
            return result

        result["status"] = "COMPATIBLE"
        result["compatible"] = True
        result["reason"] = (
            "The inventory confirms Terraform management and the catalog "
            "specifies Terraform. Approval is still required."
        )
        return result

    result["status"] = "UNSUPPORTED_EXECUTION_METHOD"
    result["reason"] = (
        f"The catalog execution method '{execution_method}' is not supported "
        "by this compatibility assessment."
    )
    result["unresolved_prerequisites"].append(
        "Review the catalog execution method and confirm a supported "
        "management workflow."
    )
    return result

def build_proposal(
    findings,
    inventory,
    catalog,
    verification,
    destination_discovery=None,
):
    finding, source_resource = find_real_finding(findings, catalog)
    bucket_name = bucket_name_from_resource(source_resource)
    inventory_resource = find_inventory_resource(
        inventory, bucket_name, finding, catalog
    )

    usable, verification_reasons, age_seconds = validate_verification(
        verification, finding, source_resource, bucket_name
    )

    live_status = verification.get("status", "UNKNOWN")
    if not usable:
        decision = "HOLD_FOR_REVIEW"
        decision_reason = (
            "Live evidence could not be accepted. Resolve the evidence issues "
            "before deciding on remediation."
        )
    elif live_status == "COMPLIANT":
        decision = "NO_ACTION_CURRENT_CONFIGURATION_COMPLIANT"
        decision_reason = (
            "The accepted live verification reports that server access "
            "logging is enabled. Review the original finding and evidence "
            "freshness before closing the finding."
        )
    else:
        decision = "REMEDIATION_REVIEW_REQUIRED"
        decision_reason = (
            "The accepted live verification reports that server access "
            "logging is disabled. A destination bucket and its configuration "
            "must be assessed before remediation can be approved."
        )

    remediation = catalog["remediation"]
    risk = catalog["risk_assessment"]
    governance = catalog["governance"]
    validation = catalog["validation"]
    rollback = catalog["rollback"]

    management_assessment = assess_management_compatibility(
        inventory_resource, remediation
    )

    if management_assessment["status"] in (
        "INCOMPATIBLE",
        "UNSUPPORTED_EXECUTION_METHOD",
    ):
        decision = "HOLD_FOR_REVIEW"
        decision_reason = management_assessment["reason"]


    if destination_discovery is None:
        destination_discovery = {
            "status": "UNAVAILABLE",
            "reason": "Destination discovery evidence was not supplied.",
            "candidate_count": 0,
            "approved_candidates": [],
        }

    discovery_status = destination_discovery.get("status", "INVALID")
    approved_candidates = destination_discovery.get(
        "approved_candidates", []
    )

    if not isinstance(approved_candidates, list):
        approved_candidates = []
        discovery_status = "INVALID"

    unresolved_prerequisites = []

    unresolved_prerequisites.extend(
        management_assessment["unresolved_prerequisites"]
    )

    if discovery_status != "VALID":
        unresolved_prerequisites.append(
            "Destination discovery evidence is unavailable, invalid, or stale; "
            "rerun discovery before evaluating destination candidates."
        )

    if not approved_candidates:
        unresolved_prerequisites.append(
            "Select and approve a suitable destination bucket in the same Region."
        )

    unresolved_prerequisites.extend([
        "Verify destination bucket permissions and retention settings.",
        "Confirm the destination bucket is suitable for access logs.",
        "Plan the change through the resource's approved management mechanism.",
    ])


    if decision == "NO_ACTION_CURRENT_CONFIGURATION_COMPLIANT":
        proposal_status = "REVIEW_REQUIRED"
    else:
        proposal_status = "DRAFT"

    proposal = {
        "proposal_id": f"PROP-AWS-S3-LOGGING-{uuid4().hex[:12].upper()}",
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
            "resource_type": source_resource.get("resource_type"),
            "resource_id": source_resource.get("resource_id"),
            "resource_name": bucket_name,
        },
        "evidence": {
            "status": "live" if usable else "rejected",
            "live_configuration_checked": True,
            "evidence_source": verification.get("evidence_source"),
            "logging_enabled": verification.get(
                "live_configuration", {}
            ).get("logging_enabled"),
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
            "rationale": remediation["rationale"],
            "desired_configuration": remediation["desired_configuration"],
            "execution_method": remediation["execution_method"],
        },


        "management_context": {
            "management_mechanism": inventory_resource.get(
                "management_mechanism"
            ),
            "terraform_management_status": inventory_resource.get(
                "terraform_management_status"
            ),
            "compatibility_assessment": management_assessment,
            "note": (
                "Management metadata is inventory evidence, not permission "
                "to change the resource. Any change must use the confirmed "
                "management workflow and avoid unmanaged drift."
            ),
        },



        "risk_assessment": {
            "risk_level": risk["risk_level"],
            "potential_side_effects": risk["potential_side_effects"],
            "preconditions": risk["preconditions"],
            "unresolved_prerequisites": unresolved_prerequisites,
            "destination_discovery": {
                "status": discovery_status,
                "reason": destination_discovery.get("reason"),
                "candidate_count": destination_discovery.get(
                    "candidate_count", 0
                ),
                "approved_candidate_count": len(approved_candidates),
            },
        },

        "governance": {
            "approval_required": True,
            "approval_status": "PENDING",
            "execution_allowed": False,
        },
        "validation": validation,
        "rollback": rollback,
    }

    # Enforce safe behavior even if the catalog changes later.
    proposal["governance"]["execution_allowed"] = False
    proposal["execution_status"] = "NOT_EXECUTED"

    return proposal


def main():
    findings = load_json(FINDINGS_PATH)
    inventory = load_json(INVENTORY_PATH)
    catalog = load_json(CATALOG_PATH)

    verification = load_json(VERIFICATION_PATH)
    destination_discovery = load_destination_discovery()

    proposal = build_proposal(
        findings,
        inventory,
        catalog,
        verification,
        destination_discovery,
    )

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(
        json.dumps(proposal, indent=2) + "\n",
        encoding="utf-8",
    )

    print(f"Proposal ID: {proposal['proposal_id']}")
    print(f"Finding: {proposal['finding']['title']}")
    print(f"Decision: {proposal['remediation_decision']['decision']}")
    print(f"Proposal status: {proposal['proposal_status']}")
    print(f"Evidence status: {proposal['evidence_status']}")
    print("Approval required: True")
    print("Execution allowed: False")
    print(f"Proposal written to: {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
