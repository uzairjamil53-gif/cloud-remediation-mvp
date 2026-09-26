import copy
import json
import tempfile
import unittest
import subprocess
import sys
import os
from unittest.mock import patch
from pathlib import Path

from remediation.reconcile_proposal import (
    apply_reconciliation,
    build_reconciled_proposal,
    fetch_live_securityhub_finding,
    validate_evidence,
    validate_live_securityhub_finding,
)




PROPOSAL_ID = "PROP-TEST-001"
FINDING_ID = "finding-test-001"
RESOURCE_ID = "arn:aws:s3:::test-bucket"
ACCOUNT_ID = "123456789012"
REGION = "us-east-1"


def sample_proposal():
    return {
        "proposal_id": PROPOSAL_ID,
        "proposal_status": "DRAFT",
        "execution_status": "NOT_EXECUTED",
        "finding": {
            "finding_id": FINDING_ID,
            "security_control_id": "S3.5",
            "compliance_status": "FAILED",
            "workflow_status": "NEW",
        },
        "affected_resource": {
            "resource_id": RESOURCE_ID,
            "account_id": ACCOUNT_ID,
            "region": REGION,
        },
        "evidence": {
            "tls_required": False,
        },
        "live_verification": {
            "status": "NON_COMPLIANT",
        },
        "governance": {
            "approval_required": True,
            "approval_status": "PENDING",
            "execution_allowed": False,
        },
    }


def sample_events():
    return [
        {
            "event_type": "EXECUTION",
            "execution_id": "EXEC-TEST-001",
            "proposal_id": PROPOSAL_ID,
            "finding_id": FINDING_ID,
            "resource_id": RESOURCE_ID,
            "aws_account": ACCOUNT_ID,
            "region": REGION,
            "execution_status": "APPLIED",
            "verification_status": "FAILED",
            "completed_at": "2026-10-31T00:41:03.480367+00:00",
        },
        {
            "event_type": "VERIFICATION_COMPLETED",
            "execution_id": "EXEC-TEST-001",
            "proposal_id": PROPOSAL_ID,
            "finding_id": FINDING_ID,
            "resource_id": RESOURCE_ID,
            "aws_account": ACCOUNT_ID,
            "region": REGION,
            "execution_status": "APPLIED",
            "verification_status": "COMPLIANT",
            "verification_method": "direct_s3_bucket_policy_check",
            "securityhub_control": "S3.5",
            "securityhub_status": "PASSED",
            "securityhub_updated_at": "2026-10-31T00:43:52.654Z",
            "verified_at": "2026-10-31T01:49:53.225432+00:00",
        },
    ]

class TestFetchLiveSecurityHubFinding(unittest.TestCase):
    def setUp(self):
        self.finding = {
            "Id": FINDING_ID,
            "AwsAccountId": ACCOUNT_ID,
            "Region": REGION,
            "Compliance": {
                "SecurityControlId": "S3.5",
                "Status": "PASSED",
            },
            "Workflow": {
                "Status": "RESOLVED",
            },
            "Resources": [
                {
                    "Type": "AwsS3Bucket",
                    "Id": RESOURCE_ID,
                }
            ],
        }

    @patch("findings.securityhub_adapter.aws_json")
    def test_returns_exact_finding(self, mock_aws_json):
        mock_aws_json.return_value = {
            "Findings": [self.finding],
        }

        result = fetch_live_securityhub_finding(
            FINDING_ID,
            REGION,
        )

        self.assertEqual(result, self.finding)
        mock_aws_json.assert_called_once()

        args = mock_aws_json.call_args.args
        self.assertIn("--region", args)
        self.assertIn(REGION, args)
        self.assertIn("--filters", args)

    @patch("findings.securityhub_adapter.aws_json")
    def test_no_exact_match_raises_value_error(self, mock_aws_json):
        mock_aws_json.return_value = {
            "Findings": [
                {
                    "Id": "different-finding-id",
                }
            ],
        }

        with self.assertRaises(ValueError):
            fetch_live_securityhub_finding(
                FINDING_ID,
                REGION,
            )

    @patch("findings.securityhub_adapter.aws_json")
    def test_duplicate_exact_matches_raise_value_error(
        self,
        mock_aws_json,
    ):
        mock_aws_json.return_value = {
            "Findings": [
                self.finding,
                self.finding,
            ],
        }

        with self.assertRaises(ValueError):
            fetch_live_securityhub_finding(
                FINDING_ID,
                REGION,
            )

class TestValidateLiveSecurityHubFinding(unittest.TestCase):
    def setUp(self):
        self.proposal = sample_proposal()
        self.proposal["finding"]["security_control_id"] = "S3.5"

        self.live_finding = {
            "Id": FINDING_ID,
            "AwsAccountId": ACCOUNT_ID,
            "Region": REGION,
            "Compliance": {
                "SecurityControlId": "S3.5",
                "Status": "PASSED",
            },
            "Workflow": {
                "Status": "RESOLVED",
            },
            "RecordState": "ACTIVE",
            "UpdatedAt": "2026-11-08T17:24:35.985Z",
            "Resources": [
                {
                    "Type": "AwsS3Bucket",
                    "Id": RESOURCE_ID,
                }
            ],
        }

    def test_valid_live_finding_passes(self):
        valid, result = validate_live_securityhub_finding(
            self.proposal,
            self.live_finding,
        )

        self.assertTrue(valid)
        self.assertEqual(result["finding_id"], FINDING_ID)
        self.assertEqual(result["account_id"], ACCOUNT_ID)
        self.assertEqual(result["region"], REGION)
        self.assertEqual(result["security_control_id"], "S3.5")
        self.assertEqual(result["resource_id"], RESOURCE_ID)
        self.assertEqual(result["compliance_status"], "PASSED")
        self.assertEqual(result["workflow_status"], "RESOLVED")

    def test_identity_mismatches_fail(self):
        live_finding = copy.deepcopy(self.live_finding)
        live_finding["AwsAccountId"] = "999999999999"
        live_finding["Resources"][0]["Id"] = (
            "arn:aws:s3:::different-bucket"
        )

        valid, errors = validate_live_securityhub_finding(
            self.proposal,
            live_finding,
        )

        self.assertFalse(valid)
        self.assertTrue(
            any("account ID" in error for error in errors)
        )
        self.assertTrue(
            any("resource ID" in error for error in errors)
        )

    def test_non_resolved_live_finding_fails(self):
        live_finding = copy.deepcopy(self.live_finding)
        live_finding["Workflow"]["Status"] = "NEW"

        valid, errors = validate_live_securityhub_finding(
            self.proposal,
            live_finding,
        )

        self.assertFalse(valid)
        self.assertTrue(
            any("workflow status" in error for error in errors)
        )

    def test_non_passed_compliance_fails(self):
        live_finding = copy.deepcopy(self.live_finding)
        live_finding["Compliance"]["Status"] = "FAILED"

        valid, errors = validate_live_securityhub_finding(
            self.proposal,
            live_finding,
        )

        self.assertFalse(valid)
        self.assertTrue(
            any("compliance status" in error for error in errors)
        )

class TestValidateEvidence(unittest.TestCase):
    def setUp(self):
        self.proposal = sample_proposal()
        self.events = sample_events()

    def test_valid_evidence_passes(self):
        valid, result = validate_evidence(
            self.proposal,
            self.events,
            "PASSED",
            "RESOLVED",
        )

    def test_verification_before_execution_fails(self):
        events = copy.deepcopy(self.events)

        events[0]["completed_at"] = (
            "2026-10-31T02:00:00+00:00"
        )

        events[1]["verified_at"] = (
            "2026-10-31T01:00:00+00:00"
        )

        valid, result = validate_evidence(
            self.proposal,
            events,
            "PASSED",
            "RESOLVED",
        )

        self.assertFalse(valid)
        self.assertTrue(
            any(
                "after execution" in error
                for error in result
            )
        )


    def test_verification_of_earlier_execution_does_not_validate_latest(self):
        events = copy.deepcopy(self.events)

        events.append(
            {
                "event_type": "EXECUTION",
                "proposal_id": PROPOSAL_ID,
                "finding_id": FINDING_ID,
                "resource_id": RESOURCE_ID,
                "aws_account": ACCOUNT_ID,
                "region": REGION,
                "execution_status": "APPLIED",
                "completed_at": "2026-10-31T02:00:00+00:00",
            }
        )

        valid, result = validate_evidence(
            self.proposal,
            events,
            "PASSED",
            "RESOLVED",
        )

        self.assertFalse(valid)
        self.assertTrue(
            any(
                "after execution" in error
                for error in result
            )
        )

    def test_verification_with_different_execution_id_does_not_validate(self):
        events = copy.deepcopy(self.events)

        events.append(
            {
                "event_type": "EXECUTION",
                "execution_id": "EXEC-TEST-002",
                "proposal_id": PROPOSAL_ID,
                "finding_id": FINDING_ID,
                "resource_id": RESOURCE_ID,
                "aws_account": ACCOUNT_ID,
                "region": REGION,
                "execution_status": "APPLIED",
                "completed_at": "2026-10-31T01:00:00+00:00",
            }
        )

        valid, result = validate_evidence(
            self.proposal,
            events,
            "PASSED",
            "RESOLVED",
        )

        self.assertFalse(valid)
        self.assertTrue(
            any(
                "execution_id" in error
                for error in result
            )
        )

    def test_verification_missing_execution_id_does_not_validate(self):
        events = copy.deepcopy(self.events)

        events.append(
            {
                "event_type": "EXECUTION",
                "execution_id": "EXEC-TEST-002",
                "proposal_id": PROPOSAL_ID,
                "finding_id": FINDING_ID,
                "resource_id": RESOURCE_ID,
                "aws_account": ACCOUNT_ID,
                "region": REGION,
                "execution_status": "APPLIED",
                "completed_at": "2026-10-31T01:00:00+00:00",
            }
        )

    def test_tied_execution_timestamps_do_not_use_wrong_execution_id(self):
        events = copy.deepcopy(self.events)

        events[0]["execution_id"] = "EXEC-TEST-001"
        events[0]["completed_at"] = "2026-10-31T02:00:00+00:00"

        events.append(
            {
                "event_type": "EXECUTION",
                "execution_id": "EXEC-TEST-002",
                "proposal_id": PROPOSAL_ID,
                "finding_id": FINDING_ID,
                "resource_id": RESOURCE_ID,
                "aws_account": ACCOUNT_ID,
                "region": REGION,
                "execution_status": "APPLIED",
                "completed_at": "2026-10-31T02:00:00+00:00",
            }
        )
        events[1]["verified_at"] = "2026-10-31T03:00:00+00:00"

        valid, result = validate_evidence(
            self.proposal,
            events,
            "PASSED",
            "RESOLVED",
        )

        self.assertFalse(valid)

        self.assertTrue(
            any(
                "execution_id" in error
                for error in result
            )
        )



        events[-1]["execution_id"] = "EXEC-TEST-002"
        events[1].pop("execution_id", None)

        valid, result = validate_evidence(
            self.proposal,
            events,
            "PASSED",
            "RESOLVED",
        )

        self.assertFalse(valid)
        self.assertTrue(
            any(
                "execution_id" in error
                for error in result
            )
        )
    def test_malformed_execution_timestamp_fails(self):
        events = copy.deepcopy(self.events)

        events[0]["completed_at"] = "invalid-timestamp"

        valid, result = validate_evidence(
            self.proposal,
            events,
            "PASSED",
            "RESOLVED",
        )

        self.assertFalse(valid)
        self.assertTrue(
            any(
                "invalid completed_at timestamp" in error
                for error in result
            )
        )

    def test_numeric_execution_timestamp_fails(self):
        events = copy.deepcopy(self.events)

        events[0]["completed_at"] = 1234567890

        valid, result = validate_evidence(
            self.proposal,
            events,
            "PASSED",
            "RESOLVED",
        )

        self.assertFalse(valid)
        self.assertTrue(
            any(
                "invalid completed_at timestamp" in error
                for error in result
            )
        )

    def test_timezone_naive_execution_timestamp_fails(self):
        events = copy.deepcopy(self.events)

        events[0]["completed_at"] = (
            "2026-10-31T00:41:03.480367"
        )

        valid, result = validate_evidence(
            self.proposal,
            events,
            "PASSED",
            "RESOLVED",
        )

        self.assertFalse(valid)
        self.assertTrue(
            any(
                "invalid completed_at timestamp" in error
                for error in result
            )
        )

    def test_malformed_verification_timestamp_fails(self):
        events = copy.deepcopy(self.events)

        events[1]["verified_at"] = "invalid-timestamp"

        valid, result = validate_evidence(
            self.proposal,
            events,
            "PASSED",
            "RESOLVED",
        )

        self.assertFalse(valid)
        self.assertTrue(
            any(
                "verification event" in error
                for error in result
            )
        )

    def test_numeric_verification_timestamp_fails(self):
        events = copy.deepcopy(self.events)

        events[1]["verified_at"] = 1234567890

        valid, result = validate_evidence(
            self.proposal,
            events,
            "PASSED",
            "RESOLVED",
        )

        self.assertFalse(valid)
        self.assertTrue(
            any(
                "verification event" in error
                for error in result
            )
        )

    def test_timezone_naive_verification_timestamp_fails(self):
        events = copy.deepcopy(self.events)

        events[1]["verified_at"] = (
            "2026-10-31T01:49:53.225432"
        )

        valid, result = validate_evidence(
            self.proposal,
            events,
            "PASSED",
            "RESOLVED",
        )

        self.assertFalse(valid)
        self.assertTrue(
            any(
                "verification event" in error
                for error in result
            )
        )

    def test_wrong_resource_identity_fails(self):
        proposal = copy.deepcopy(self.proposal)
        proposal["affected_resource"]["resource_id"] = (
            "arn:aws:s3:::different-bucket"
        )

        valid, result = validate_evidence(
            proposal,
            self.events,
            "PASSED",
            "RESOLVED",
        )

        self.assertFalse(valid)
        self.assertTrue(any("APPLIED" in error for error in result))

    def test_missing_execution_evidence_fails(self):
        valid, result = validate_evidence(
            self.proposal,
            [],
            "PASSED",
            "RESOLVED",
        )

        self.assertFalse(valid)
        self.assertTrue(any("APPLIED" in error for error in result))

    def test_failed_securityhub_status_fails(self):
        valid, result = validate_evidence(
            self.proposal,
            self.events,
            "FAILED",
            "RESOLVED",
        )

        self.assertFalse(valid)
        self.assertTrue(
            any("PASSED" in error for error in result)
        )

    def test_unresolved_workflow_fails(self):
        valid, result = validate_evidence(
            self.proposal,
            self.events,
            "PASSED",
            "NEW",
        )

        self.assertFalse(valid)
        self.assertTrue(
            any("RESOLVED" in error for error in result)
        )

    def test_wrong_verification_method_fails(self):
        events = copy.deepcopy(self.events)
        events[-1]["verification_method"] = "untrusted_method"

        valid, result = validate_evidence(
            self.proposal,
            events,
            "PASSED",
            "RESOLVED",
        )

        self.assertFalse(valid)
        self.assertTrue(
            any("direct-verification" in error for error in result)
        )


class TestBuildReconciledProposal(unittest.TestCase):
    def test_preserves_historical_evidence_and_governance(self):
        proposal = sample_proposal()

        valid, evidence = validate_evidence(
            proposal,
            sample_events(),
            "PASSED",
            "RESOLVED",
        )

        self.assertTrue(valid)


        updated = build_reconciled_proposal(
            proposal,
            evidence,
            "2026-11-02T00:00:00+00:00",
        )

        self.assertEqual(updated["proposal_status"], "VERIFIED")
        self.assertEqual(updated["execution_status"], "APPLIED")

        self.assertEqual(
            updated["finding"]["compliance_status"],
            "FAILED",
        )

        self.assertEqual(
            updated["live_verification"]["status"],
            "NON_COMPLIANT",
        )

        self.assertEqual(
            updated["governance"]["approval_status"],
            "PENDING",
        )

        self.assertFalse(
            updated["governance"]["execution_allowed"]
        )

        self.assertEqual(
            updated["resolution"]["direct_verification_status"],
            "COMPLIANT",
        )


class TestApplyReconciliation(unittest.TestCase):
    def test_apply_updates_proposal_and_appends_audit(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            proposal_path = temp_path / "proposal.json"
            reconciliation_audit_path = (
                temp_path / "reconciliation_events.jsonl"
            )

            proposal = sample_proposal()

            valid, evidence = validate_evidence(
                proposal,
                sample_events(),
                "PASSED",
                "RESOLVED",
            )

            self.assertTrue(valid)

            evidence["securityhub_operator_attestation"] = {
                "confirmed": True,
                "confirmation_method": "interactive_cli",
                "confirmed_at": "2026-11-07T18:00:00+00:00",
                "scope": {
                    "finding_id": FINDING_ID,
                    "resource_id": RESOURCE_ID,
                    "account_id": ACCOUNT_ID,
                    "region": REGION,
                    "compliance_status": "PASSED",
                    "workflow_status": "RESOLVED",
                },
            }

            proposal_path.write_text(
                json.dumps(proposal, indent=2),
                encoding="utf-8",
            )

            backup_path, event = apply_reconciliation(
                proposal_path,
                reconciliation_audit_path,
                proposal,
                evidence,
            )

            updated = json.loads(
                proposal_path.read_text(encoding="utf-8")
            )

            self.assertTrue(backup_path.exists())
            self.assertEqual(updated["proposal_status"], "VERIFIED")
            self.assertEqual(updated["execution_status"], "APPLIED")
            self.assertEqual(
                updated["governance"]["approval_status"],
                "PENDING",
            )
            self.assertFalse(
                updated["governance"]["execution_allowed"]
            )

            audit_lines = reconciliation_audit_path.read_text(
                encoding="utf-8"
            ).splitlines()

            self.assertEqual(len(audit_lines), 1)

            audit_event = json.loads(audit_lines[0])

            self.assertEqual(
                audit_event["event_type"],
                "PROPOSAL_RECONCILIATION",
            )

            self.assertEqual(
                audit_event["proposal_id"],
                PROPOSAL_ID,
            )

            self.assertEqual(
                event["execution_status"],
                "APPLIED",
            )

            self.assertEqual(
                audit_event["securityhub_operator_attestation"],
                evidence["securityhub_operator_attestation"],
            )

            self.assertEqual(
                updated["resolution"]["securityhub_operator_attestation"],
                evidence["securityhub_operator_attestation"],
            )

    def test_cli_rejects_missing_operator_confirmation(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            fake_aws_path = temp_path / "aws"

            fake_response = {
                "Findings": [
                    {
                        "Id": FINDING_ID,
                        "AwsAccountId": ACCOUNT_ID,
                        "Region": REGION,
                        "Compliance": {
                            "SecurityControlId": "S3.5",
                            "Status": "PASSED",
                        },
                        "Workflow": {
                            "Status": "RESOLVED",
                        },
                        "RecordState": "ACTIVE",
                        "Resources": [
                            {
                                "Type": "AwsS3Bucket",
                                "Id": RESOURCE_ID,
                            }
                        ],
                    }
                ]
            }

            fake_aws_path.write_text(
                "#!/usr/bin/env python3\n"
                "import json\n"
                f"print(json.dumps({fake_response!r}))\n",
                encoding="utf-8",
            )

            fake_aws_path.chmod(0o755)

            proposal_path = temp_path / "proposal.json"
            execution_audit_path = temp_path / "execution_events.jsonl"
            reconciliation_audit_path = (
                temp_path / "reconciliation_events.jsonl"
            )

            proposal = sample_proposal()

            proposal_path.write_text(
                json.dumps(proposal, indent=2),
                encoding="utf-8",
            )

            execution_audit_path.write_text(
                "\n".join(
                    json.dumps(event)
                    for event in sample_events()
                )
                + "\n",
                encoding="utf-8",
            )

            script_path = (
                Path(__file__).resolve().parents[1]
                / "remediation"
                / "reconcile_proposal.py"
            )

            test_env = os.environ.copy()
            test_env["PATH"] = (
                str(temp_path)
                + os.pathsep
                + test_env.get("PATH", "")
            )

            result = subprocess.run(
                [
                    sys.executable,
                    str(script_path),
                    "--proposal",
                    str(proposal_path),
                    "--audit",
                    str(execution_audit_path),
                    "--reconciliation-audit",
                    str(reconciliation_audit_path),
                    "--expected-proposal-id",
                    PROPOSAL_ID,
                    "--apply",
                ],
                input="NO\n",
                capture_output=True,
                text=True,
                check=False,
                env=test_env,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "Operator attestation not confirmed",
                result.stderr,
            )

            unchanged_proposal = json.loads(
                proposal_path.read_text(encoding="utf-8")
            )

            self.assertEqual(unchanged_proposal, proposal)
            self.assertFalse(reconciliation_audit_path.exists())

            backup_path = proposal_path.with_suffix(
                proposal_path.suffix
                + ".pre-reconciliation.bak"
            )

            self.assertFalse(backup_path.exists())

    def test_reconciliation_refuses_already_resolved_proposal(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            proposal_path = temp_path / "proposal.json"
            audit_path = temp_path / "reconciliation_events.jsonl"

            proposal = sample_proposal()
            proposal["finding"]["security_control_id"] = "S3.5"
            proposal["resolution"] = {"status": "VERIFIED"}

            valid, evidence = validate_evidence(
                proposal,
                sample_events(),
                "PASSED",
                "RESOLVED",
            )

            self.assertTrue(valid)

            proposal_path.write_text(
                json.dumps(proposal),
                encoding="utf-8",
            )

            with self.assertRaises(ValueError):
                apply_reconciliation(
                    proposal_path,
                    audit_path,
                    proposal,
                    evidence,
                )

            self.assertFalse(audit_path.exists())


if __name__ == "__main__":
    unittest.main()
