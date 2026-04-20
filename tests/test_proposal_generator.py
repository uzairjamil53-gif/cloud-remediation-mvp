import json
import tempfile
import unittest
from pathlib import Path
from datetime import datetime, timedelta, timezone

from remediation.proposal_generator import (
    assess_live_verification,
    decide_remediation,
)

from remediation.proposal_generator import (
    ROOT,
    build_proposal,
    find_inventory_resource,
    load_json,
    validate_inputs,
)


class ProposalGeneratorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.finding = load_json(
            ROOT / "findings" / "fixtures"
            / "synthetic_s3_public_access_finding.json"
        )
        cls.inventory = load_json(
            ROOT / "inventory" / "inventory.json"
        )
        cls.catalog = load_json(
            ROOT / "remediation" / "catalog"
            / "s3_block_public_access.json"
        )

    def test_synthetic_finding_generates_safe_draft(self):
        validate_inputs(self.finding, self.catalog)

        resource = find_inventory_resource(
            self.finding, self.inventory
        )

        proposal = build_proposal(
            self.finding,
            resource,
            self.catalog,
            {},
        )

        self.assertEqual(proposal["proposal_status"], "DRAFT")
        self.assertEqual(
            proposal["execution_status"], "NOT_EXECUTED"
        )
        self.assertTrue(proposal["test_fixture"])
        self.assertEqual(
            proposal["evidence_status"],
            "SIMULATED_NOT_LIVE_VERIFIED",
        )
        self.assertFalse(
            proposal["evidence"]["live_configuration_checked"]
        )
        self.assertTrue(
            proposal["governance"]["approval_required"]
        )
        self.assertEqual(
            proposal["governance"]["approval_status"], "PENDING"
        )
        self.assertFalse(
            proposal["governance"]["execution_allowed"]
        )

    def test_synthetic_finding_matches_expected_bucket(self):
        resource = find_inventory_resource(
            self.finding, self.inventory
        )

        self.assertEqual(
            resource["resource_id"],
            "cloud-remediation-mvp-848f82dd",
        )
        self.assertEqual(
            resource["management_mechanism"], "terraform"
        )

    def test_missing_resource_match_is_rejected(self):
        altered_finding = dict(self.finding)
        altered_finding["resource_id"] = "nonexistent-bucket"

        with self.assertRaisesRegex(
            ValueError, "found 0"
        ):
            find_inventory_resource(
                altered_finding, self.inventory
            )

    def test_ambiguous_resource_match_is_rejected(self):
        duplicated_inventory = dict(self.inventory)
        duplicated_inventory["resources"] = (
            self.inventory["resources"]
            + [dict(self.inventory["resources"][0])]
        )

        with self.assertRaisesRegex(
            ValueError, "found 2"
        ):
            find_inventory_resource(
                self.finding, duplicated_inventory
            )

    def test_non_synthetic_finding_is_rejected(self):
        altered_finding = dict(self.finding)
        altered_finding["test_fixture"] = False

        with self.assertRaisesRegex(
            ValueError, "explicitly labeled test fixture"
        ):
            validate_inputs(altered_finding, self.catalog)

    def test_live_evidence_cannot_masquerade_as_simulated(self):
        altered_finding = dict(self.finding)
        altered_finding["evidence"] = dict(
            self.finding["evidence"]
        )
        altered_finding["evidence"]["evidence_status"] = "verified"

        with self.assertRaisesRegex(
            ValueError, "labeled simulated"
        ):
            validate_inputs(altered_finding, self.catalog)

    def test_catalog_resource_type_must_match(self):
        altered_catalog = dict(self.catalog)
        altered_catalog["resource_type"] = "AWS::EC2::VPC"

        with self.assertRaisesRegex(
            ValueError, "resource types differ"
        ):
            validate_inputs(self.finding, altered_catalog)


class LiveVerificationDecisionTests(unittest.TestCase):
    def setUp(self):
        self.resource = {
            "cloud": "aws",
            "account_id": "665808487090",
            "region": "us-east-1",
            "resource_id": "cloud-remediation-mvp-848f82dd",
        }
        self.verification = {
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "status": "COMPLIANT",
            "live_configuration_checked": True,
            "cloud": "aws",
            "account_id": "665808487090",
            "region": "us-east-1",
            "resource_id": "cloud-remediation-mvp-848f82dd",
            "evidence_source": "aws_s3api_get_public_access_block",
        }

    def test_fresh_compliant_verification_means_no_action(self):
        assessment = assess_live_verification(
            self.verification, self.resource
        )
        decision = decide_remediation(assessment)

        self.assertEqual(assessment["status"], "COMPLIANT")
        self.assertTrue(assessment["usable"])
        self.assertEqual(
            decision["decision"],
            "NO_ACTION_CURRENT_CONFIGURATION_COMPLIANT",
        )

    def test_fresh_non_compliant_verification_requires_review(self):
        self.verification["status"] = "NON_COMPLIANT"

        assessment = assess_live_verification(
            self.verification, self.resource
        )
        decision = decide_remediation(assessment)

        self.assertTrue(assessment["usable"])
        self.assertEqual(
            decision["decision"],
            "REMEDIATION_REVIEW_REQUIRED",
        )

    def test_stale_verification_is_held_for_review(self):
        old_time = datetime.now(timezone.utc) - timedelta(minutes=16)
        self.verification["checked_at"] = old_time.isoformat()

        assessment = assess_live_verification(
            self.verification, self.resource
        )
        decision = decide_remediation(assessment)

        self.assertFalse(assessment["usable"])
        self.assertEqual(assessment["status"], "UNKNOWN")
        self.assertEqual(decision["decision"], "HOLD_FOR_REVIEW")

    def test_resource_identity_mismatch_is_held_for_review(self):
        self.verification["resource_id"] = "different-bucket"

        assessment = assess_live_verification(
            self.verification, self.resource
        )
        decision = decide_remediation(assessment)

        self.assertFalse(assessment["usable"])
        self.assertEqual(assessment["status"], "UNKNOWN")
        self.assertEqual(decision["decision"], "HOLD_FOR_REVIEW")

    def test_missing_verification_is_held_for_review(self):
        assessment = assess_live_verification({}, self.resource)
        decision = decide_remediation(assessment)

        self.assertFalse(assessment["usable"])
        self.assertEqual(decision["decision"], "HOLD_FOR_REVIEW")



if __name__ == "__main__":
    unittest.main()
