import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from remediation import execution_engine


class TestVerifyPlanIntegrity(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.plan_path = Path(self.temp_dir.name) / "test.tfplan"
        self.plan_path.write_bytes(b"reviewed terraform plan")

        self.expected_hash = hashlib.sha256(
            self.plan_path.read_bytes()
        ).hexdigest()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_matching_hash_passes(self):
        with patch.object(
            execution_engine, "PLAN_PATH", self.plan_path
        ):
            result = execution_engine.verify_plan_integrity(
                self.expected_hash
            )

        self.assertTrue(result)

    def test_modified_plan_hash_fails(self):
        self.plan_path.write_bytes(b"modified terraform plan")

        with patch.object(
            execution_engine, "PLAN_PATH", self.plan_path
        ):
            with self.assertRaisesRegex(
                ValueError,
                "changed after inspection",
            ):
                execution_engine.verify_plan_integrity(
                    self.expected_hash
                )

    def test_missing_plan_fails(self):
        self.plan_path.unlink()

        with patch.object(
            execution_engine, "PLAN_PATH", self.plan_path
        ):
            with self.assertRaisesRegex(
                ValueError,
                "Saved Terraform plan does not exist",
            ):
                execution_engine.verify_plan_integrity(
                    self.expected_hash
                )

class TestExecutionCancellationAudit(unittest.TestCase):

    def test_wrong_approval_records_cancellation(self):
        proposal = {
            "proposal_id": "PROP-TEST-123",
            "finding": {
                "finding_id": "FINDING-TEST-123",
            },
        }

        with (
            patch.object(
                execution_engine,
                "verify_aws_identity",
            ),
            patch.object(
                execution_engine,
                "verify_terraform_state",
            ),
            patch.object(
                execution_engine,
                "verify_current_s3_5_finding",
            ),
            patch.object(
                execution_engine,
                "verify_no_existing_source_policy",
            ),
            patch.object(
                execution_engine,
                "inspect_saved_plan",
                return_value="test-plan-hash",
            ),
            patch(
                "builtins.input",
                return_value="WRONG-APPROVAL",
            ),
            patch.object(
                execution_engine,
                "append_execution_audit",
            ) as audit_mock,
        ):
            execution_engine.execute_saved_plan(proposal)

        audit_mock.assert_called_once()

        event = audit_mock.call_args.args[0]

        self.assertEqual(
            event["event_type"],
            "EXECUTION_CANCELLED",
        )
        self.assertEqual(
            event["execution_status"],
            "CANCELLED",
        )
        self.assertEqual(
            event["cancellation_reason"],
            "PROPOSAL_ID_CONFIRMATION_MISMATCH",
        )

    def test_plan_integrity_failure_records_abort(self):
        proposal = {
            "proposal_id": "PROP-TEST-123",
            "finding": {
                "finding_id": "FINDING-TEST-123",
            },
        }

        with (
            patch.object(
                execution_engine,
                "verify_aws_identity",
            ),
            patch.object(
                execution_engine,
                "verify_terraform_state",
            ),
            patch.object(
                execution_engine,
                "verify_current_s3_5_finding",
            ),
            patch.object(
                execution_engine,
                "verify_no_existing_source_policy",
            ),
            patch.object(
                execution_engine,
                "inspect_saved_plan",
                return_value="test-plan-hash",
            ),
            patch(
                "builtins.input",
                return_value="PROP-TEST-123",
            ),
            patch.object(
                execution_engine,
                "verify_plan_integrity",
                side_effect=ValueError(
                    "Saved Terraform plan changed after inspection."
                ),
            ),
            patch.object(
                execution_engine,
                "append_execution_audit",
            ) as audit_mock,
            patch.object(
                execution_engine.subprocess,
                "run",
            ) as subprocess_mock,
        ):
            with self.assertRaisesRegex(
                ValueError,
                "changed after inspection",
            ):
                execution_engine.execute_saved_plan(proposal)

        audit_mock.assert_called_once()
        subprocess_mock.assert_not_called()

        event = audit_mock.call_args.args[0]

        self.assertEqual(
            event["event_type"],
            "EXECUTION_ABORTED",
        )
        self.assertEqual(
            event["execution_status"],
            "ABORTED",
        )
        self.assertEqual(
            event["abort_reason"],
            "SAVED_PLAN_INTEGRITY_FAILURE",
        )

if __name__ == "__main__":
    unittest.main()
