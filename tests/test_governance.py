import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from remediation.governance import get_review_history, main, record_review
from unittest.mock import patch


PROJECT_ROOT = Path(__file__).resolve().parent.parent

PROPOSAL_PATH = (
    PROJECT_ROOT
    / "remediation"
    / "proposals"
    / "s3_server_access_logging_proposal.json"
)


class GovernanceTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

        self.temp_path = Path(self.temp_dir.name)
        self.proposal_path = self.temp_path / "proposal.json"
        self.audit_path = self.temp_path / "audit" / "approval_events.jsonl"

        self.proposal = {
            "proposal_id": "PROP-TEST-123",
            "test_fixture": False,
            "proposal_status": "DRAFT",
            "evidence_status": "LIVE_VERIFIED",
            "remediation_decision": {
                "decision": "REMEDIATION_REVIEW_REQUIRED",
                "reason": "The finding requires review before remediation.",
            },
            "execution_status": "NOT_EXECUTED",
            "governance": {
                "approval_required": True,
                "approval_status": "PENDING",
                "execution_allowed": False,
            },
            "risk_assessment": {
                "unresolved_prerequisites": [
                    "Approve a destination bucket.",
                ]
            },
        }

        self.write_proposal()

    def write_proposal(self):
        self.proposal_path.write_text(
            json.dumps(self.proposal, indent=2),
            encoding="utf-8",
        )

    def review(self, decision="RETURN_FOR_CHANGES", **overrides):
        arguments = {
            "proposal_path": self.proposal_path,
            "decision": decision,
            "reviewer": "security-reviewer",
            "rationale": "Reviewing proposal prerequisites.",
            "expected_proposal_id": "PROP-TEST-123",
            "audit_path": self.audit_path,
        }
        arguments.update(overrides)
        return record_review(**arguments)

    def test_return_for_changes_records_audit_event(self):
        event = self.review()

        self.assertEqual(event["decision"], "RETURN_FOR_CHANGES")
        self.assertEqual(event["proposal_id"], "PROP-TEST-123")
        self.assertEqual(event["unresolved_prerequisite_count"], 1)
        self.assertFalse(event["execution_allowed"])
        self.assertEqual(event["execution_status"], "NOT_EXECUTED")
        self.assertTrue(self.audit_path.exists())

        lines = self.audit_path.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 1)
        self.assertEqual(json.loads(lines[0]), event)

    def test_reject_records_audit_event(self):
        event = self.review(
            decision="REJECT",
            rationale="The proposal is not suitable.",
        )

        self.assertEqual(event["decision"], "REJECT")
        self.assertFalse(event["execution_allowed"])

    def test_approval_for_planning_is_blocked_with_prerequisites(self):
        with self.assertRaisesRegex(ValueError, "prerequisites remain unresolved"):
            self.review(decision="APPROVE_FOR_PLANNING")

        self.assertFalse(self.audit_path.exists())

    def test_approval_for_planning_allowed_when_prerequisites_are_resolved(self):
        self.proposal["risk_assessment"]["unresolved_prerequisites"] = []
        self.write_proposal()

        event = self.review(decision="APPROVE_FOR_PLANNING")

        self.assertEqual(event["decision"], "APPROVE_FOR_PLANNING")
        self.assertFalse(event["execution_allowed"])
        self.assertEqual(event["execution_status"], "NOT_EXECUTED")

    def test_wrong_proposal_id_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Proposal ID"):
            self.review(expected_proposal_id="PROP-WRONG")

        self.assertFalse(self.audit_path.exists())

    def test_missing_reviewer_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Reviewer identity"):
            self.review(reviewer=" ")

    def test_missing_rationale_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "rationale"):
            self.review(rationale=" ")

    def test_unknown_decision_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Unsupported decision"):
            self.review(decision="EXECUTE_NOW")

    def test_execution_enabled_proposal_is_rejected(self):
        self.proposal["governance"]["execution_allowed"] = True
        self.write_proposal()

        with self.assertRaisesRegex(ValueError, "execution safeguard"):
            self.review()

    def test_non_draft_proposal_is_rejected(self):
        self.proposal["proposal_status"] = "APPROVED"
        self.write_proposal()

        with self.assertRaisesRegex(ValueError, "Only DRAFT"):
            self.review()

    def test_review_does_not_modify_original_proposal(self):
        original = self.proposal_path.read_text(encoding="utf-8")

        self.review()

        current = self.proposal_path.read_text(encoding="utf-8")
        self.assertEqual(current, original)

    def test_multiple_reviews_append_separate_events(self):
        self.review()
        self.review(
            decision="REJECT",
            rationale="Second review decision.",
        )

        lines = self.audit_path.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 2)

    def test_real_proposal_has_expected_review_fields(self):
        if not PROPOSAL_PATH.exists():
            self.skipTest("Real proposal file is not available.")

        proposal = json.loads(PROPOSAL_PATH.read_text(encoding="utf-8"))

        self.assertTrue(proposal.get("proposal_id"))
        self.assertEqual(proposal.get("proposal_status"), "DRAFT")
        self.assertEqual(proposal.get("evidence_status"), "LIVE_VERIFIED")
        self.assertFalse(proposal["governance"]["execution_allowed"])
        self.assertEqual(proposal.get("execution_status"), "NOT_EXECUTED")

    def test_missing_remediation_decision_is_rejected(self):
        self.proposal.pop("remediation_decision")
        self.write_proposal()

        with self.assertRaisesRegex(
            ValueError, "Remediation decision section"
        ):
            self.review()

        self.assertFalse(self.audit_path.exists())

    def test_wrong_remediation_decision_is_rejected(self):
        self.proposal["remediation_decision"] = {
            "decision": "NO_ACTION_REQUIRED",
            "reason": "No remediation is needed.",
        }
        self.write_proposal()

        with self.assertRaisesRegex(
            ValueError, "not marked as requiring remediation review"
        ):
            self.review()

        self.assertFalse(self.audit_path.exists())

    def test_malformed_risk_assessment_is_rejected(self):
        self.proposal["risk_assessment"] = []
        self.write_proposal()

        with self.assertRaisesRegex(
            ValueError, "Risk assessment section"
        ):
            self.review()

        self.assertFalse(self.audit_path.exists())

    def test_empty_unresolved_prerequisite_is_rejected(self):
        self.proposal["risk_assessment"]["unresolved_prerequisites"] = [
            "Approve a destination bucket.",
            "   ",
        ]
        self.write_proposal()

        with self.assertRaisesRegex(
            ValueError, "non-empty string"
        ):
            self.review()

        self.assertFalse(self.audit_path.exists())

    def test_non_string_unresolved_prerequisite_is_rejected(self):
        self.proposal["risk_assessment"]["unresolved_prerequisites"] = [
            "Approve a destination bucket.",
            123,
        ]
        self.write_proposal()

        with self.assertRaisesRegex(
            ValueError, "non-empty string"
        ):
            self.review()

        self.assertFalse(self.audit_path.exists())


    def test_review_history_returns_events_in_chronological_order(self):
        first = self.review(
            decision="RETURN_FOR_CHANGES",
            rationale="Initial review.",
        )
        second = self.review(
            decision="REJECT",
            rationale="Follow-up review.",
        )

        history = get_review_history("PROP-TEST-123", self.audit_path)

        self.assertEqual(len(history), 2)
        self.assertEqual(history[0]["decision"], first["decision"])
        self.assertEqual(history[1]["decision"], second["decision"])

    def test_review_history_filters_by_proposal_id(self):
        self.review()

        other_event = {
            "event_type": "REMEDIATION_PROPOSAL_REVIEW",
            "proposal_id": "PROP-OTHER-456",
            "decision": "REJECT",
        }
        with self.audit_path.open("a", encoding="utf-8") as file:
            file.write(json.dumps(other_event) + "\n")

        history = get_review_history("PROP-TEST-123", self.audit_path)

        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["proposal_id"], "PROP-TEST-123")

    def test_review_history_returns_empty_list_when_log_is_missing(self):
        history = get_review_history("PROP-TEST-123", self.audit_path)

        self.assertEqual(history, [])

    def test_review_history_rejects_malformed_json(self):
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        self.audit_path.write_text(
            '{"event_type": "REMEDIATION_PROPOSAL_REVIEW"\n',
            encoding="utf-8",
        )

        with self.assertRaisesRegex(ValueError, "Invalid JSON"):
            get_review_history("PROP-TEST-123", self.audit_path)

    def test_cli_displays_review_summary(self):
        self.review(
            decision="RETURN_FOR_CHANGES",
            rationale="Initial review requires changes.",
        )
        self.review(
            decision="REJECT",
            rationale="The proposal was rejected.",
        )

        with patch(
            "sys.argv",
            ["governance", "PROP-TEST-123"],
        ), patch(
            "remediation.governance.DEFAULT_AUDIT_PATH",
            self.audit_path,
        ), patch("builtins.print") as mock_print:
            result = main()

        self.assertEqual(result, 0)

        output = "\n".join(
            " ".join(str(arg) for arg in call.args)
            for call in mock_print.call_args_list
        )

        self.assertIn("Total reviews: 2", output)
        self.assertIn("Most recent decision: REJECT", output)
        self.assertIn("Most recent reviewer: security-reviewer", output)
        self.assertIn("Execution allowed: False", output)
        self.assertIn("Execution status: NOT_EXECUTED", output)


    def test_cli_displays_review_history(self):
        self.review(
            decision="RETURN_FOR_CHANGES",
            rationale="Destination bucket requires review.",
        )

        with patch(
            "sys.argv",
            ["governance", "PROP-TEST-123"],
        ), patch(
            "remediation.governance.DEFAULT_AUDIT_PATH",
            self.audit_path,
        ), patch("builtins.print") as mock_print:
            result = main()

        self.assertEqual(result, 0)
        output = "\n".join(
            " ".join(str(arg) for arg in call.args)
            for call in mock_print.call_args_list
        )
        self.assertIn("PROP-TEST-123", output)
        self.assertIn("RETURN_FOR_CHANGES", output)
        self.assertIn("Destination bucket requires review.", output)

    def test_cli_reports_missing_review_history(self):
        with patch(
            "sys.argv",
            ["governance", "PROP-NO-HISTORY"],
        ), patch(
            "remediation.governance.DEFAULT_AUDIT_PATH",
            self.audit_path,
        ), patch("builtins.print") as mock_print:
            result = main()

        self.assertEqual(result, 0)
        mock_print.assert_called_once_with(
            "No review history found for proposal PROP-NO-HISTORY."
        )

    def test_cli_reports_malformed_audit_log(self):
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        self.audit_path.write_text("{invalid json}\n", encoding="utf-8")

        with patch(
            "sys.argv",
            ["governance", "PROP-TEST-123"],
        ), patch(
            "remediation.governance.DEFAULT_AUDIT_PATH",
            self.audit_path,
        ), patch("sys.stderr") as mock_stderr:
            result = main()

        self.assertEqual(result, 1)
        mock_stderr.write.assert_called()

    def test_cli_records_return_for_changes(self):
        with patch(
            "sys.argv",
            [
                "governance",
                "PROP-TEST-123",
                "--decision",
                "RETURN_FOR_CHANGES",
                "--reviewer",
                "security-reviewer",
                "--rationale",
                "Destination and permissions require review.",
                "--proposal-path",
                str(self.proposal_path),
            ],
        ), patch(
            "remediation.governance.DEFAULT_AUDIT_PATH",
            self.audit_path,
        ):
                result = main()

        self.assertEqual(result, 0)

        history = get_review_history(
            "PROP-TEST-123",
            self.audit_path,
        )

        self.assertEqual(len(history), 1)
        self.assertEqual(
            history[0]["decision"],
            "RETURN_FOR_CHANGES",
        )
        self.assertEqual(
            history[0]["reviewer"],
            "security-reviewer",
        )
        self.assertFalse(history[0]["execution_allowed"])
        self.assertEqual(
            history[0]["execution_status"],
            "NOT_EXECUTED",
        )

    def test_cli_rejects_approval_with_unresolved_prerequisites(self):
        with patch(
            "sys.argv",
            [
                "governance",
                "PROP-TEST-123",
                "--decision",
                "APPROVE_FOR_PLANNING",
                "--reviewer",
                "security-reviewer",
                "--rationale",
                "Attempting to approve planning.",
                "--proposal-path",
                str(self.proposal_path),
            ],
        ), patch(
            "remediation.governance.DEFAULT_AUDIT_PATH",
            self.audit_path,
        ):
            result = main()

        self.assertNotEqual(result, 0)
        self.assertFalse(self.audit_path.exists())

    def test_cli_status_displays_proposal_and_safety_details(self):
        self.proposal.update({
            "finding": {
                "title": "Test security finding",
                "severity": "MEDIUM",
            },
            "affected_resource": {
                "cloud": "AWS",
                "region": "us-east-1",
                "resource_id": "test-resource-123",
            },
            "live_verification": {
                "status": "NON_COMPLIANT",
                "checked_at": "2026-10-18T12:00:00+00:00",
            },
        })
        self.write_proposal()

        with patch(
            "sys.argv",
            [
                "governance",
                "PROP-TEST-123",
                "--status",
                "--proposal-path",
                str(self.proposal_path),
            ],
        ), patch(
            "remediation.governance.DEFAULT_AUDIT_PATH",
            self.audit_path,
        ), patch("builtins.print") as mock_print:
            result = main()

        self.assertEqual(result, 0)

        output = "\n".join(
            " ".join(str(arg) for arg in call.args)
            for call in mock_print.call_args_list
        )

        self.assertIn("PROP-TEST-123", output)
        self.assertIn("DRAFT", output)
        self.assertIn("NON_COMPLIANT", output)
        self.assertIn("NOT_EXECUTED", output)
        self.assertIn("Execution allowed: False", output)
        self.assertIn("No review history", output)

    def test_cli_status_does_not_modify_proposal_or_audit_log(self):
        original = self.proposal_path.read_text(encoding="utf-8")

        with patch(
            "sys.argv",
            [
                "governance",
                "PROP-TEST-123",
                "--status",
                "--proposal-path",
                str(self.proposal_path),
            ],
        ), patch(
            "remediation.governance.DEFAULT_AUDIT_PATH",
            self.audit_path,
        ), patch("builtins.print"):
            result = main()

        self.assertEqual(result, 0)
        self.assertEqual(
            self.proposal_path.read_text(encoding="utf-8"),
            original,
        )
        self.assertFalse(self.audit_path.exists())

if __name__ == "__main__":
    unittest.main()
