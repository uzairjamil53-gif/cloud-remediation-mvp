"""Record remediation proposal reviews without executing AWS changes."""

import json
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent

DEFAULT_AUDIT_PATH = (
    PROJECT_ROOT / "remediation" / "audit" / "approval_events.jsonl"
)

ALLOWED_DECISIONS = {
    "APPROVE_FOR_PLANNING",
    "REJECT",
    "RETURN_FOR_CHANGES",
}


def record_review(
    proposal_path,
    decision,
    reviewer,
    rationale,
    expected_proposal_id,
    audit_path=DEFAULT_AUDIT_PATH,
):
    """Validate a proposal and append a review event to a local audit log.

    This function never modifies the proposal and never authorizes execution.
    """

    proposal_file = Path(proposal_path)

    if decision not in ALLOWED_DECISIONS:
        raise ValueError(
            f"Unsupported decision: {decision}. "
            f"Choose one of: {', '.join(sorted(ALLOWED_DECISIONS))}."
        )

    if not isinstance(reviewer, str) or not reviewer.strip():
        raise ValueError("Reviewer identity is required.")

    if not isinstance(rationale, str) or not rationale.strip():
        raise ValueError("A review rationale is required.")

    if not isinstance(expected_proposal_id, str) or not expected_proposal_id.strip():
        raise ValueError("Expected proposal ID is required.")

    try:
        proposal = json.loads(proposal_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("Proposal could not be read as valid JSON.") from exc

    if not isinstance(proposal, dict):
        raise ValueError("Proposal must be a JSON object.")

    if proposal.get("proposal_id") != expected_proposal_id:
        raise ValueError("Proposal ID does not match the expected ID.")

    if proposal.get("test_fixture") is not False:
        raise ValueError("Only real, non-fixture proposals may be reviewed.")

    if proposal.get("proposal_status") != "DRAFT":
        raise ValueError("Only DRAFT proposals may be reviewed.")

    if proposal.get("evidence_status") != "LIVE_VERIFIED":
        raise ValueError("Proposal does not contain accepted live evidence.")

    governance = proposal.get("governance")
    if not isinstance(governance, dict):
        raise ValueError("Proposal governance section is missing or invalid.")

    if governance.get("approval_required") is not True:
        raise ValueError("Proposal does not require approval.")

    if governance.get("execution_allowed") is not False:
        raise ValueError("Proposal execution safeguard is missing.")

    if proposal.get("execution_status") != "NOT_EXECUTED":
        raise ValueError("Proposal execution status is not safe.")

    remediation_decision = proposal.get("remediation_decision")
    if not isinstance(remediation_decision, dict):
        raise ValueError("Remediation decision section is missing or invalid.")

    if remediation_decision.get("decision") != "REMEDIATION_REVIEW_REQUIRED":
        raise ValueError(
            "Proposal is not marked as requiring remediation review."
        )

    risk_assessment = proposal.get("risk_assessment")
    if not isinstance(risk_assessment, dict):
        raise ValueError("Risk assessment section is missing or invalid.")

    unresolved = risk_assessment.get("unresolved_prerequisites")
    if not isinstance(unresolved, list):
        raise ValueError("Unresolved prerequisites are missing or invalid.")

    if any(
        not isinstance(item, str) or not item.strip()
        for item in unresolved
    ):
        raise ValueError(
            "Every unresolved prerequisite must be a non-empty string."
        )

    if decision == "APPROVE_FOR_PLANNING" and unresolved:
        raise ValueError(
            "Cannot approve planning while prerequisites remain unresolved. "
            "Use RETURN_FOR_CHANGES or REJECT."
        )

    event = {
        "event_type": "REMEDIATION_PROPOSAL_REVIEW",
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "proposal_id": proposal["proposal_id"],
        "decision": decision,
        "reviewer": reviewer.strip(),
        "rationale": rationale.strip(),
        "unresolved_prerequisite_count": len(unresolved),
        "execution_allowed": False,
        "execution_status": "NOT_EXECUTED",
        "proposal_modified": False,
        "aws_resources_modified": False,
    }

    audit_file = Path(audit_path)
    audit_file.parent.mkdir(parents=True, exist_ok=True)

    with audit_file.open("a", encoding="utf-8") as file:
        file.write(json.dumps(event, sort_keys=True) + "\n")

    return event


def get_review_history(proposal_id, audit_path=DEFAULT_AUDIT_PATH):
    """Return audit events for one proposal in chronological order.

    This function only reads the audit log. It does not modify proposals
    or authorize or execute AWS changes.
    """

    if not isinstance(proposal_id, str) or not proposal_id.strip():
        raise ValueError("Proposal ID is required.")

    audit_file = Path(audit_path)

    if not audit_file.exists():
        return []

    events = []

    try:
        with audit_file.open("r", encoding="utf-8") as file:
            for line_number, line in enumerate(file, start=1):
                if not line.strip():
                    continue

                try:
                    event = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(
                        f"Invalid JSON in audit log at line {line_number}."
                    ) from exc

                if not isinstance(event, dict):
                    raise ValueError(
                        f"Audit entry at line {line_number} must be a JSON object."
                    )

                if event.get("event_type") != "REMEDIATION_PROPOSAL_REVIEW":
                    continue

                if event.get("proposal_id") == proposal_id:
                    events.append(event)

    except OSError as exc:
        raise ValueError("Audit log could not be read.") from exc

    return events


def main():
    """Display review history or record a review decision from the CLI."""

    import argparse
    import sys

    default_proposal_path = (
        PROJECT_ROOT
        / "remediation"
        / "proposals"
        / "s3_server_access_logging_proposal.json"
    )

    parser = argparse.ArgumentParser(
        description=(
            "Display remediation proposal review history or record a review."
        )
    )
    parser.add_argument(
        "proposal_id",
        help="The exact proposal ID to inspect or review.",
    )
    parser.add_argument(
        "--decision",
        choices=sorted(ALLOWED_DECISIONS),
        help="Record a review decision instead of displaying history.",
    )
    parser.add_argument(
        "--reviewer",
        help="Identity of the person reviewing the proposal.",
    )
    parser.add_argument(
        "--rationale",
        help="Explanation supporting the review decision.",
    )
    parser.add_argument(
        "--proposal-path",
        type=Path,
        default=default_proposal_path,
        help="Path to the proposal JSON file.",
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Display a read-only summary of the proposal and its review history.",
    )



    args = parser.parse_args()

    if args.status and args.decision:
        print(
            "Error: --status cannot be combined with --decision.",
            file=sys.stderr,
        )
        return 1

    if args.status:
        try:
            proposal = json.loads(
                args.proposal_path.read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError) as exc:
            print(
                f"Error: Could not read proposal JSON: {exc}",
                file=sys.stderr,
            )
            return 1

        if not isinstance(proposal, dict):
            print(
                "Error: Proposal must be a JSON object.",
                file=sys.stderr,
            )
            return 1

        if proposal.get("proposal_id") != args.proposal_id:
            print(
                "Error: Proposal ID does not match the requested ID.",
                file=sys.stderr,
            )
            return 1

        try:
            history = get_review_history(
                args.proposal_id,
                audit_path=DEFAULT_AUDIT_PATH,
            )
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1

        finding = proposal.get("finding") or {}
        resource = proposal.get("affected_resource") or {}
        verification = proposal.get("live_verification") or {}
        decision = proposal.get("remediation_decision") or {}
        risk = proposal.get("risk_assessment") or {}
        governance = proposal.get("governance") or {}
        latest = history[-1] if history else None

        print(f"Proposal status report: {args.proposal_id}")
        print("-" * 60)
        print(f"Proposal status: {proposal.get('proposal_status', 'Unknown')}")
        print(f"Evidence status: {proposal.get('evidence_status', 'Unknown')}")
        print(f"Finding: {finding.get('title', 'Unknown')}")
        print(f"Severity: {finding.get('severity', 'Unknown')}")
        print(f"Cloud: {resource.get('cloud', 'Unknown')}")
        print(f"Region: {resource.get('region', 'Unknown')}")
        print(f"Resource ID: {resource.get('resource_id', 'Unknown')}")
        print(
            "Live verification: "
            f"{verification.get('status', 'Unknown')}"
        )
        print(
            "Verification checked at: "
            f"{verification.get('checked_at', 'Unknown')}"
        )
        print(f"Remediation decision: {decision.get('decision', 'Unknown')}")
        print(f"Decision reason: {decision.get('reason', 'Not provided')}")
        print(f"Risk level: {risk.get('risk_level', 'Unknown')}")
        print("Unresolved prerequisites:")

        prerequisites = risk.get("unresolved_prerequisites", [])
        if isinstance(prerequisites, list) and prerequisites:
            for item in prerequisites:
                print(f"  - {item}")
        else:
            print("  None recorded")

        print(f"Approval required: {governance.get('approval_required', 'Unknown')}")
        print(f"Approval status: {governance.get('approval_status', 'Unknown')}")
        print(f"Execution allowed: {governance.get('execution_allowed', 'Unknown')}")
        print(f"Execution status: {proposal.get('execution_status', 'Unknown')}")

        if latest:
            print(f"Total reviews: {len(history)}")
            print(f"Most recent decision: {latest.get('decision', 'Unknown')}")
            print(f"Most recent reviewer: {latest.get('reviewer', 'Unknown')}")
            print(f"Most recent rationale: {latest.get('rationale', 'Not provided')}")
        else:
            print("Total reviews: 0")
            print(f"No review history found for proposal {args.proposal_id}.")

        print("-" * 60)
        print("Read-only report: no proposal, audit log, or AWS resources modified.")
        return 0

    if args.decision:

        if not args.reviewer or not args.rationale:
            print(
                "Error: --reviewer and --rationale are required "
                "when recording a decision.",
                file=sys.stderr,
            )
            return 1

        try:
            event = record_review(
                proposal_path=args.proposal_path,
                decision=args.decision,
                reviewer=args.reviewer,
                rationale=args.rationale,
                expected_proposal_id=args.proposal_id,
                audit_path=DEFAULT_AUDIT_PATH,
            )
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1
        except OSError as exc:
            print(f"Error: Could not record review: {exc}", file=sys.stderr)
            return 1

        print(f"Review recorded for proposal {event['proposal_id']}.")
        print(f"Decision: {event['decision']}")
        print(f"Reviewer: {event['reviewer']}")
        print(f"Execution allowed: {event['execution_allowed']}")
        print(f"Execution status: {event['execution_status']}")
        return 0

    try:
        history = get_review_history(
            args.proposal_id,
            audit_path=DEFAULT_AUDIT_PATH,
        )
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if not history:
        print(f"No review history found for proposal {args.proposal_id}.")
        return 0

    latest = history[-1]

    print(f"Review summary for {args.proposal_id}")
    print(f"Total reviews: {len(history)}")
    print(f"Most recent decision: {latest.get('decision', 'Unknown')}")
    print(f"Most recent reviewer: {latest.get('reviewer', 'Unknown')}")
    print(f"Execution allowed: {latest.get('execution_allowed', 'Unknown')}")
    print(f"Execution status: {latest.get('execution_status', 'Unknown')}")
    print()
    print(f"Review history for {args.proposal_id}")
    print("-" * 60)

    for index, event in enumerate(history, start=1):
        print(f"Review #{index}")
        print(f"  Recorded at: {event.get('recorded_at', 'Unknown')}")
        print(f"  Decision: {event.get('decision', 'Unknown')}")
        print(f"  Reviewer: {event.get('reviewer', 'Unknown')}")
        print(f"  Rationale: {event.get('rationale', 'Not provided')}")
        print(
            "  Unresolved prerequisites: "
            f"{event.get('unresolved_prerequisite_count', 'Unknown')}"
        )
        print(f"  Execution allowed: {event.get('execution_allowed', 'Unknown')}")
        print(f"  Execution status: {event.get('execution_status', 'Unknown')}")
        print()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
