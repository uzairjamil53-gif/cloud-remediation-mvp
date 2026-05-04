import json
import unittest
import tempfile
from unittest.mock import patch
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path


from remediation.real_finding_proposal_generator import (
    build_proposal,
    load_destination_discovery,
)

ROOT = Path(__file__).resolve().parent.parent


def load_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


class RealFindingProposalTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.findings = load_json(ROOT / "findings/securityhub_findings.json")
        cls.inventory = load_json(ROOT / "inventory/inventory.json")
        cls.catalog = load_json(
            ROOT / "remediation/catalog/s3_server_access_logging.json"
        )
        cls.verification = load_json(
            ROOT
            / "remediation/proposals/"
            / "s3_server_access_logging_verification.json"
        )

    def make_proposal(self, verification=None, findings=None, inventory=None):
        return build_proposal(
            deepcopy(self.findings if findings is None else findings),
            deepcopy(self.inventory if inventory is None else inventory),
            deepcopy(self.catalog),
            deepcopy(
                self.verification if verification is None else verification
            ),
        )



    def test_real_finding_generates_draft_without_execution(self):
        verification = deepcopy(self.verification)
        verification["checked_at"] = datetime.now(timezone.utc).isoformat()

        proposal = self.make_proposal(verification=verification)

        self.assertFalse(proposal["test_fixture"])
        self.assertEqual(proposal["evidence_status"], "LIVE_VERIFIED")
        self.assertEqual(proposal["proposal_status"], "DRAFT")
        self.assertEqual(
            proposal["remediation_decision"]["decision"],
            "REMEDIATION_REVIEW_REQUIRED",
        )
        self.assertTrue(proposal["governance"]["approval_required"])
        self.assertEqual(proposal["governance"]["approval_status"], "PENDING")
        self.assertFalse(proposal["governance"]["execution_allowed"])
        self.assertEqual(proposal["execution_status"], "NOT_EXECUTED")

    def test_confirmed_terraform_management_is_compatible(self):
        proposal = self.make_proposal()

        assessment = proposal["management_context"]["compatibility_assessment"]

        self.assertEqual(assessment["status"], "MECHANISM_IDENTIFIED_APPROVAL_REQUIRED")
        self.assertIsNone(assessment["compatible"])
        self.assertFalse(proposal["governance"]["execution_allowed"])
        self.assertEqual(proposal["execution_status"], "NOT_EXECUTED")

    def test_unknown_management_mechanism_adds_prerequisite(self):
        inventory = deepcopy(self.inventory)
        resource = next(
            item for item in inventory["resources"]
            if item.get("resource_type") == "AWS::S3::Bucket"
        )
        resource["management_mechanism"] = "unknown"
        resource["terraform_management_status"] = "not_assessed"

        proposal = self.make_proposal(inventory=inventory)
        assessment = proposal["management_context"]["compatibility_assessment"]

        self.assertEqual(assessment["status"], "UNKNOWN")
        self.assertTrue(assessment["unresolved_prerequisites"])
        self.assertFalse(proposal["governance"]["execution_allowed"])

    def test_terraform_catalog_rejects_confirmed_non_terraform_mechanism(self):
        catalog = deepcopy(self.catalog)
        catalog["remediation"]["execution_method"] = "terraform"

        inventory = deepcopy(self.inventory)
        resource = next(
            item for item in inventory["resources"]
            if item.get("resource_type") == "AWS::S3::Bucket"
        )
        resource["management_mechanism"] = "cloudformation"
        resource["terraform_management_status"] = "not_found_in_current_state"

        verification = deepcopy(self.verification)
        verification["checked_at"] = datetime.now(timezone.utc).isoformat()

        proposal = build_proposal(
            deepcopy(self.findings),
            inventory,
            catalog,
            verification,
        )

        assessment = proposal["management_context"]["compatibility_assessment"]

        self.assertEqual(assessment["status"], "INCOMPATIBLE")
        self.assertFalse(assessment["compatible"])
        self.assertEqual(
            proposal["remediation_decision"]["decision"],
            "HOLD_FOR_REVIEW",
        )
        self.assertFalse(proposal["governance"]["execution_allowed"])
        self.assertEqual(proposal["execution_status"], "NOT_EXECUTED")

    def test_missing_management_mechanism_adds_prerequisite(self):
        inventory = deepcopy(self.inventory)
        resource = next(
            item for item in inventory["resources"]
            if item.get("resource_type") == "AWS::S3::Bucket"
        )
        resource.pop("management_mechanism", None)

        proposal = self.make_proposal(inventory=inventory)
        assessment = proposal["management_context"]["compatibility_assessment"]

        self.assertEqual(assessment["status"], "UNKNOWN")
        self.assertTrue(assessment["unresolved_prerequisites"])
        self.assertFalse(proposal["governance"]["execution_allowed"])

    def test_noncompliant_evidence_requires_destination_prerequisites(self):
        proposal = self.make_proposal()

        prerequisites = proposal["risk_assessment"]["unresolved_prerequisites"]
        self.assertTrue(prerequisites)
        self.assertTrue(
            any("destination bucket" in item.lower() for item in prerequisites)
        )

    def test_compliant_verification_does_not_recommend_remediation(self):
        verification = deepcopy(self.verification)
        verification["status"] = "COMPLIANT"
        verification["live_configuration"]["logging_enabled"] = True
        verification["live_configuration"]["target_bucket"] = "approved-logs"
        verification["checked_at"] = datetime.now(timezone.utc).isoformat()

        proposal = self.make_proposal(verification=verification)

        self.assertEqual(
            proposal["remediation_decision"]["decision"],
            "NO_ACTION_CURRENT_CONFIGURATION_COMPLIANT",
        )
        self.assertEqual(proposal["proposal_status"], "REVIEW_REQUIRED")
        self.assertFalse(proposal["governance"]["execution_allowed"])

    def test_stale_verification_is_held_for_review(self):
        verification = deepcopy(self.verification)
        verification["checked_at"] = (
            datetime.now(timezone.utc) - timedelta(minutes=30)
        ).isoformat()

        proposal = self.make_proposal(verification=verification)

        self.assertEqual(
            proposal["remediation_decision"]["decision"],
            "HOLD_FOR_REVIEW",
        )
        self.assertEqual(proposal["evidence_status"], "LIVE_EVIDENCE_REJECTED")
        self.assertFalse(proposal["governance"]["execution_allowed"])

    def test_mismatched_finding_identity_is_held_for_review(self):
        verification = deepcopy(self.verification)
        verification["finding"]["finding_id"] = "different-finding"

        proposal = self.make_proposal(verification=verification)

        self.assertEqual(
            proposal["remediation_decision"]["decision"],
            "HOLD_FOR_REVIEW",
        )

    def test_mismatched_resource_identity_is_held_for_review(self):
        verification = deepcopy(self.verification)
        verification["resource"]["bucket_name"] = "different-bucket"

        proposal = self.make_proposal(verification=verification)

        self.assertEqual(
            proposal["remediation_decision"]["decision"],
            "HOLD_FOR_REVIEW",
        )

    def test_unknown_verification_is_held_for_review(self):
        verification = deepcopy(self.verification)
        verification["status"] = "UNKNOWN"
        verification["live_configuration"]["logging_enabled"] = None

        proposal = self.make_proposal(verification=verification)

        self.assertEqual(
            proposal["remediation_decision"]["decision"],
            "HOLD_FOR_REVIEW",
        )

    def test_ambiguous_matching_findings_are_rejected(self):
        findings = deepcopy(self.findings)
        records = findings["findings"]
        original = next(
            f for f in records if f.get("security_control_id") == "S3.9"
        )
        records.append(deepcopy(original))

        with self.assertRaises(ValueError):
            self.make_proposal(findings=findings)

    def test_missing_inventory_match_is_rejected(self):
        inventory = deepcopy(self.inventory)
        inventory["resources"] = [
            resource
            for resource in inventory["resources"]
            if resource.get("resource_type") != "AWS::S3::Bucket"
        ]

        with self.assertRaises(ValueError):
            self.make_proposal(inventory=inventory)


    def test_catalog_cannot_enable_execution(self):
        catalog = deepcopy(self.catalog)
        catalog["governance"]["execution_allowed"] = True

        verification = deepcopy(self.verification)
        verification["checked_at"] = datetime.now(timezone.utc).isoformat()

        proposal = build_proposal(
            deepcopy(self.findings),
            deepcopy(self.inventory),
            catalog,
            verification,
        )

        self.assertFalse(proposal["governance"]["execution_allowed"])
        self.assertEqual(proposal["execution_status"], "NOT_EXECUTED")
        self.assertTrue(proposal["governance"]["approval_required"])
        self.assertEqual(proposal["governance"]["approval_status"], "PENDING")


    def test_missing_destination_discovery_returns_unavailable(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "missing.json"

            with patch(
                "remediation.real_finding_proposal_generator."
                "DESTINATION_DISCOVERY_PATH",
                path,
            ):
                result = load_destination_discovery()

        self.assertEqual(result["status"], "UNAVAILABLE")
        self.assertEqual(result["approved_candidates"], [])

    def test_stale_destination_discovery_returns_stale(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "discovery.json"
            evidence = {
                "checked_at": (
                    datetime.now(timezone.utc) - timedelta(minutes=30)
                ).isoformat(),
                "account_id": "665808487090",
                "region_scope": "us-east-1",
                "status": "DISCOVERY_COMPLETE",
                "execution_allowed": False,
                "source_bucket": "source-test-bucket",
                "candidates": [],
            }
            path.write_text(json.dumps(evidence), encoding="utf-8")

            with patch(
                "remediation.real_finding_proposal_generator."
                "DESTINATION_DISCOVERY_PATH",
                path,
            ):
                result = load_destination_discovery()

        self.assertEqual(result["status"], "STALE")
        self.assertEqual(result["approved_candidates"], [])

    def test_malformed_destination_discovery_returns_invalid(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "discovery.json"
            path.write_text("{invalid json", encoding="utf-8")

            with patch(
                "remediation.real_finding_proposal_generator."
                "DESTINATION_DISCOVERY_PATH",
                path,
            ):
                result = load_destination_discovery()

        self.assertEqual(result["status"], "INVALID")
        self.assertEqual(result["approved_candidates"], [])


if __name__ == "__main__":
    unittest.main()
