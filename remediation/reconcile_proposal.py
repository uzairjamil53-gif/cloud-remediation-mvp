import argparse
import json
import os
import shutil
import tempfile
import sys
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent

DEFAULT_PROPOSAL = (
    PROJECT_ROOT / "remediation" / "proposals" / "s3_tls_proposal.json"
)

DEFAULT_EXECUTION_AUDIT = (
    PROJECT_ROOT / "remediation" / "audit" / "execution_events.jsonl"
)

DEFAULT_RECONCILIATION_AUDIT = (
    PROJECT_ROOT
    / "remediation"
    / "audit"
    / "proposal_reconciliation_events.jsonl"
)

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

def utc_now():
    return datetime.now(timezone.utc).isoformat()

def fetch_live_securityhub_finding(finding_id, region):
    """Fetch one Security Hub finding by its exact finding ID."""
    from findings.securityhub_adapter import aws_json

    response = aws_json(
        "securityhub",
        "get-findings",
        "--region",
        region,
        "--filters",
        json.dumps(
            {
                "Id": [
                    {
                        "Value": finding_id,
                        "Comparison": "EQUALS",
                    }
                ]
            }
        ),
        "--max-results",
        "10",
    )

    findings = response.get("Findings", [])

    exact_matches = [
        finding
        for finding in findings
        if finding.get("Id") == finding_id
    ]

    if len(exact_matches) != 1:
        raise ValueError(
            "Expected exactly one live Security Hub finding "
            f"for {finding_id}, found {len(exact_matches)}."
        )

    return exact_matches[0]

def validate_live_securityhub_finding(proposal, live_finding):
    """Validate live Security Hub finding identity and resolution status."""
    proposal_finding = proposal.get("finding", {})
    proposal_resource = proposal.get("affected_resource", {})

    live_compliance = live_finding.get("Compliance", {})
    live_workflow = live_finding.get("Workflow", {})

    proposal_finding_id = proposal_finding.get("finding_id")
    proposal_account_id = str(proposal_resource.get("account_id", ""))
    proposal_region = proposal_resource.get("region")
    proposal_control_id = proposal_finding.get("security_control_id")
    proposal_resource_id = proposal_resource.get("resource_id")

    live_finding_id = live_finding.get("Id")
    live_account_id = str(live_finding.get("AwsAccountId", ""))
    live_region = live_finding.get("Region")
    live_control_id = live_compliance.get("SecurityControlId")
    live_compliance_status = live_compliance.get("Status")
    live_workflow_status = live_workflow.get("Status")

    live_resource_ids = {
        resource.get("Id")
        for resource in live_finding.get("Resources", [])
        if resource.get("Id")
    }

    errors = []

    if live_finding_id != proposal_finding_id:
        errors.append("Live Security Hub finding ID does not match proposal.")

    if live_account_id != proposal_account_id:
        errors.append("Live Security Hub account ID does not match proposal.")

    if live_region != proposal_region:
        errors.append("Live Security Hub region does not match proposal.")

    if live_control_id != proposal_control_id:
        errors.append("Live Security Hub control ID does not match proposal.")

    if proposal_resource_id not in live_resource_ids:
        errors.append("Live Security Hub resource ID does not match proposal.")

    if live_compliance_status != "PASSED":
        errors.append("Live Security Hub compliance status must be PASSED.")

    if live_workflow_status != "RESOLVED":
        errors.append("Live Security Hub workflow status must be RESOLVED.")

    if errors:
        return False, errors

    return True, {
        "finding_id": live_finding_id,
        "account_id": live_account_id,
        "region": live_region,
        "security_control_id": live_control_id,
        "resource_id": proposal_resource_id,
        "compliance_status": live_compliance_status,
        "workflow_status": live_workflow_status,
        "updated_at": live_finding.get("UpdatedAt"),
    }

def load_json(path):
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def load_jsonl(path):
    events = []

    if not path.exists():
        raise FileNotFoundError(f"Audit file not found: {path}")

    with path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            if not line.strip():
                continue

            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON in {path}, line {line_number}: {exc}"
                ) from exc

    return events


def validate_evidence(
    proposal,
    events,
    securityhub_status,
    securityhub_workflow_status,
):
    proposal_id = proposal.get("proposal_id")
    finding = proposal.get("finding", {})
    resource = proposal.get("affected_resource", {})

    finding_id = finding.get("finding_id")
    resource_id = resource.get("resource_id")
    account_id = resource.get("account_id")
    region = resource.get("region")

    missing = [
        name
        for name, value in {
            "proposal_id": proposal_id,
            "finding_id": finding_id,
            "resource_id": resource_id,
            "account_id": account_id,
            "region": region,
        }.items()
        if not value
    ]

    if missing:
        return False, [
            f"Proposal is missing required identity fields: {', '.join(missing)}"
        ]

    matching_events = [
        event
        for event in events
        if event.get("proposal_id") == proposal_id
        and event.get("finding_id") == finding_id
        and event.get("resource_id") == resource_id
        and str(event.get("aws_account")) == str(account_id)
        and event.get("region") == region
    ]


    applied_events = [
        event
        for event in matching_events
        if event.get("execution_status") == "APPLIED"
        and event.get("completed_at")
    ]

    verification_events = [
        event
        for event in matching_events
        if event.get("event_type") == "VERIFICATION_COMPLETED"
        and event.get("execution_status") == "APPLIED"
        and event.get("verification_status") == "COMPLIANT"
        and event.get("verification_method")
        == "direct_s3_bucket_policy_check"
        and event.get("verified_at")
    ]

    errors = []

    if not applied_events:
        errors.append("No matching APPLIED execution event was found.")

    if not verification_events:
        errors.append(
            "No matching successful direct-verification event was found."
        )

    if securityhub_status != "PASSED":
        errors.append("Security Hub compliance status must be PASSED.")

    if securityhub_workflow_status != "RESOLVED":
        errors.append("Security Hub workflow status must be RESOLVED.")

    if errors:
        return False, errors





    def parse_timestamp(event, field):
        value = event.get(field)

        if not isinstance(value, str):
            return None

        try:
            timestamp = datetime.fromisoformat(
                value.replace("Z", "+00:00")
        )
        except ValueError:
            return None

        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            return None

        return timestamp


    parsed_execution_times = [
        parse_timestamp(execution_event, "completed_at")
        for execution_event in applied_events
    ]

    if any(timestamp is None for timestamp in parsed_execution_times):
        return False, [
            "Execution evidence contains an invalid completed_at timestamp."
        ]


    latest_execution_time = max(parsed_execution_times)

    latest_execution_count = parsed_execution_times.count(
        latest_execution_time
    )

    if latest_execution_count > 1:
        return False, [
            "Multiple APPLIED execution events share the latest "
            "completed_at timestamp; cannot determine the latest "
            "execution_id."
        ]

    latest_execution_event = applied_events[
        parsed_execution_times.index(latest_execution_time)
    ]

    latest_execution_id = latest_execution_event.get("execution_id")

    valid_verifications = []

    for verification_event in verification_events:
        verification_time = parse_timestamp(
            verification_event,
            "verified_at",
        )

        if verification_time is None:
            continue

        verification_execution_id = verification_event.get(
            "execution_id"
        )

        if latest_execution_id is not None:
            if verification_execution_id != latest_execution_id:
                continue

        if verification_time >= latest_execution_time:
            valid_verifications.append(
                (verification_time, verification_event)
            )

    if not valid_verifications:
        if latest_execution_id is not None:
            return False, [
                "No successful verification event with matching "
                "execution_id occurred after execution."
            ]

        return False, [
            "No successful verification event occurred after execution."
        ]

    verification_event = max(
        valid_verifications,
        key=lambda pair: pair[0],
    )[1]


    return True, {
        "proposal_id": proposal_id,
        "finding_id": finding_id,
        "resource_id": resource_id,
        "account_id": account_id,
        "region": region,
        "execution_status": "APPLIED",
        "direct_verification_status": "COMPLIANT",
        "verification_method": verification_event.get(
            "verification_method"
        ),
        "securityhub_compliance_status": securityhub_status,
        "securityhub_workflow_status": securityhub_workflow_status,
        "securityhub_control": verification_event.get(
            "securityhub_control"
        ),
        "securityhub_updated_at": verification_event.get(
            "securityhub_updated_at"
        ),
        "verified_at": verification_event.get("verified_at"),
    }


def build_reconciled_proposal(proposal, evidence, reconciled_at):
    updated = json.loads(json.dumps(proposal))

    updated["proposal_status"] = "VERIFIED"
    updated["execution_status"] = "APPLIED"
    updated["warning"] = (
        "Remediation was executed and verified. "
        "See the resolution section for supporting evidence."
    )

    updated["resolution"] = {
        **evidence,
        "reconciled_at": reconciled_at,
        "reconciliation_source": "execution_audit_and_supplied_securityhub_evidence",
    }

    # Execution does not imply formal governance approval.
    updated.setdefault("governance", {})
    updated["governance"]["approval_required"] = True
    updated["governance"]["approval_status"] = "PENDING"
    updated["governance"]["execution_allowed"] = False

    return updated


def atomic_write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)

    fd, temp_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )

    try:
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            json.dump(data, file, indent=2)
            file.write("\n")
            file.flush()
            os.fsync(file.fileno())

        os.replace(temp_name, path)

    except Exception:
        if os.path.exists(temp_name):
            os.unlink(temp_name)
        raise


def append_jsonl(path, event):
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("a", encoding="utf-8") as file:
        file.write(json.dumps(event) + "\n")
        file.flush()
        os.fsync(file.fileno())


def apply_reconciliation(
    proposal_path,
    reconciliation_audit_path,
    proposal,
    evidence,
):
    if proposal.get("resolution"):
        raise ValueError(
            "Proposal already contains a resolution. "
            "Review it before attempting another reconciliation."
        )

    if proposal.get("proposal_status") != "DRAFT":
        raise ValueError("Only a DRAFT proposal can be reconciled.")

    if proposal.get("execution_status") != "NOT_EXECUTED":
        raise ValueError(
            "Proposal execution status is not NOT_EXECUTED."
        )

    governance = proposal.get("governance", {})

    if governance.get("approval_status") != "PENDING":
        raise ValueError("Unexpected governance approval status.")

    if governance.get("execution_allowed") is not False:
        raise ValueError("Governance execution safeguard is not intact.")

    if not proposal.get("affected_resource", {}).get("resource_id"):
        raise ValueError("Proposal has no target resource.")

    reconciled_at = utc_now()

    updated = build_reconciled_proposal(
        proposal,
        evidence,
        reconciled_at,
    )

    backup_path = proposal_path.with_suffix(
        proposal_path.suffix + ".pre-reconciliation.bak"
    )

    if not backup_path.exists():
        shutil.copy2(proposal_path, backup_path)

    event = {
        "event_type": "PROPOSAL_RECONCILIATION",
        "reconciled_at": reconciled_at,
        "proposal_id": evidence["proposal_id"],
        "finding_id": evidence["finding_id"],
        "resource_id": evidence["resource_id"],
        "aws_account": evidence["account_id"],
        "region": evidence["region"],
        "proposal_status": "VERIFIED",
        "execution_status": "APPLIED",
        "verification_status": "COMPLIANT",
        "securityhub_status": evidence["securityhub_compliance_status"],
        "securityhub_workflow_status": evidence[
            "securityhub_workflow_status"
        ],
        "securityhub_operator_attestation": evidence.get(
            "securityhub_operator_attestation"
        ),
        "governance_approval_status": "PENDING",
        "execution_allowed": False,
    }

    # Write the proposal first. If this fails, no audit event is appended.
    atomic_write_json(proposal_path, updated)

    try:
        append_jsonl(reconciliation_audit_path, event)
    except Exception:
        # Restore the original proposal if the audit append fails.
        atomic_write_json(proposal_path, proposal)
        raise

    return backup_path, event


def main():
    parser = argparse.ArgumentParser(
        description="Reconcile a proposal with execution and verification evidence."
    )

    parser.add_argument("--proposal", type=Path, default=DEFAULT_PROPOSAL)
    parser.add_argument("--audit", type=Path, default=DEFAULT_EXECUTION_AUDIT)
    parser.add_argument(
        "--reconciliation-audit",
        type=Path,
        default=DEFAULT_RECONCILIATION_AUDIT,
    )

    parser.add_argument("--expected-proposal-id", required=True)
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Write reconciled proposal and append reconciliation audit event.",
    )

    args = parser.parse_args()

    proposal = load_json(args.proposal)
    events = load_jsonl(args.audit)

    if proposal.get("proposal_id") != args.expected_proposal_id:
        raise SystemExit(
            "Proposal ID mismatch. No reconciliation was performed."
        )


    try:
        live_finding = fetch_live_securityhub_finding(
            proposal["finding"]["finding_id"],
            proposal["affected_resource"]["region"],
        )
    except Exception as exc:
        raise SystemExit(
            f"Live Security Hub lookup failed. "
            f"No reconciliation was performed: {exc}"
        ) from exc

    live_valid, live_result = validate_live_securityhub_finding(
        proposal,
        live_finding,
    )

    if not live_valid:
        print("LIVE SECURITY HUB VALIDATION FAILED")
        for error in live_result:
            print(f"- {error}")
        raise SystemExit(1)

    securityhub_status = live_finding.get(
        "Compliance", {}
    ).get("Status")

    securityhub_workflow_status = live_finding.get(
        "Workflow", {}
    ).get("Status")

    valid, result = validate_evidence(
        proposal,
        events,
        securityhub_status,
        securityhub_workflow_status,
    )

    if not valid:
        print("RECONCILIATION FAILED")
        for error in result:
            print(f"- {error}")
        raise SystemExit(1)

    print("RECONCILIATION EVIDENCE VALIDATED")
    print(json.dumps(result, indent=2))

    if not args.apply:
        print("\nDry-run only. No files or AWS resources were modified.")
        return

    print("\nSECURITY HUB EVIDENCE REVIEW")
    print(f"Proposal ID: {result['proposal_id']}")
    print(f"Finding ID:  {result['finding_id']}")
    print(f"Resource:    {result['resource_id']}")
    print(f"Account:     {result['account_id']}")
    print(f"Region:      {result['region']}")
    print(f"Compliance:  {result['securityhub_compliance_status']}")
    print(f"Workflow:    {result['securityhub_workflow_status']}")

    print(
        "\nConfirm that you independently checked the Security Hub "
        "finding and resource identity, account, region, compliance "
        "status, and workflow status."
    )

    confirmation = input(
        "Type CONFIRM to record this operator attestation: "
    ).strip()

    if confirmation != "CONFIRM":
        raise SystemExit(
            "Operator attestation not confirmed. "
            "No reconciliation was performed."
        )

    result["securityhub_operator_attestation"] = {
        "confirmed": True,
        "confirmation_method": "interactive_cli",
        "confirmed_at": utc_now(),
        "scope": {
            "finding_id": result["finding_id"],
            "resource_id": result["resource_id"],
            "account_id": result["account_id"],
            "region": result["region"],
            "compliance_status": result[
                "securityhub_compliance_status"
            ],
            "workflow_status": result[
                "securityhub_workflow_status"
            ],
        },
    }

    backup_path, event = apply_reconciliation(
        args.proposal,
        args.reconciliation_audit,
        proposal,
        result,
    )

    print("\nPROPOSAL RECONCILED SUCCESSFULLY")
    print(f"Backup: {backup_path}")
    print(f"Reconciliation audit: {args.reconciliation_audit}")
    print(json.dumps(event, indent=2))


if __name__ == "__main__":
    main()
