import unittest
from copy import deepcopy
from datetime import datetime, timedelta, timezone

from remediation.ec2_default_security_group_proposal_generator import (
    EXPECTED_ACCOUNT_ID,
    EXPECTED_FINDING_ID,
    EXPECTED_REGION,
    EXPECTED_RESOURCE_ARN,
    EXPECTED_SECURITY_GROUP_ID,
    EXPECTED_VPC_ID,
    MAX_EVIDENCE_AGE_SECONDS,
    build_proposal,
)


class EC2DefaultSecurityGroupProposalTests(unittest.TestCase):

    def setUp(self):
        self.findings = {
            "findings": [
                {
                    "finding_id": EXPECTED_FINDING_ID,
                    "source_provider": "Security Hub",
                    "title": (
                        "VPC default security groups should not allow "
                        "inbound or outbound traffic"
                    ),
                    "severity": "HIGH",
                    "workflow_status": "NEW",
                    "compliance_status": "FAILED",
                    "security_control_id": "EC2.2",
                    "cloud_provider": "aws",
                    "account_id": EXPECTED_ACCOUNT_ID,
                    "region": EXPECTED_REGION,
                    "resources": [
                        {
                            "resource_scope": "resource",
                            "resource_type": "AWS::EC2::SecurityGroup",
                            "resource_id": EXPECTED_RESOURCE_ARN,
                            "arn": EXPECTED_RESOURCE_ARN,
                            "account_id": EXPECTED_ACCOUNT_ID,
                            "region": EXPECTED_REGION,
                        }
                    ],
                }
            ]
        }

        self.inventory = {
            "resources": [
                {
                    "cloud": "aws",
                    "account_id": EXPECTED_ACCOUNT_ID,
                    "region": EXPECTED_REGION,
                    "resource_type": "AWS::EC2::SecurityGroup",
                    "resource_id": EXPECTED_SECURITY_GROUP_ID,
                    "arn": EXPECTED_RESOURCE_ARN,
                    "resource_name": "default",
                    "vpc_id": EXPECTED_VPC_ID,
                    "management_mechanism": "unknown",
                    "terraform_management_status": (
                        "not_found_in_current_state"
                    ),
                    "terraform_resource_address": None,
                    "managed_by_terraform": None,
                }
            ]
        }

        self.catalog = {
            "catalog_id": (
                "AWS-EC2-DEFAULT-SECURITY-GROUP-CLOSED-001"
            ),
            "finding_match": {
                "title_contains": (
                    "default security groups should not allow "
                    "inbound or outbound traffic"
                ),
                "severities": ["HIGH", "CRITICAL"],
            },
            "remediation": {
                "summary": (
                    "Remove all inbound and outbound rules from "
                    "the VPC default security group."
                ),
                "desired_configuration": {
                    "inbound_rules": [],
                    "outbound_rules": [],
                },
                "execution_method": (
                    "requires_approved_management_mechanism"
                ),
                "execution_status": "proposal_only",
            },
            "risk": {
                "level": "HIGH",
                "potential_side_effects": [
                    "Connectivity loss for dependent workloads"
                ],
            },
            "preconditions": [
                "Identify the approved management mechanism.",
                "Review workload dependencies.",
                "Obtain explicit approval.",
            ],
            "governance": {
                "approval_required": True,
                "approval_status": "PENDING",
                "execution_allowed": False,
            },
            "validation": {
                "checks": [
                    "Confirm ingress rules are empty.",
                    "Confirm egress rules are empty.",
                    "Confirm Security Hub EC2.2 is PASSED.",
                ]
            },
            "rollback": {
                "strategy": (
                    "Restore previously documented and approved rules."
                ),
                "requires_approval": True,
                "automatic_rollback_allowed": False,
            },
        }

        self.verification = {
            "verification_type": (
                "live_ec2_default_security_group_configuration"
            ),
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "status": "NON_COMPLIANT",
            "finding": {
                "finding_id": EXPECTED_FINDING_ID,
                "security_control_id": "EC2.2",
                "compliance_status": "FAILED",
                "workflow_status": "NEW",
                "record_state": "ACTIVE",
            },
            "resource": {
                "resource_id": EXPECTED_RESOURCE_ARN,
                "resource_type": "AWS::EC2::SecurityGroup",
                "resource_name": "default",
                "security_group_id": EXPECTED_SECURITY_GROUP_ID,
                "vpc_id": EXPECTED_VPC_ID,
                "region": EXPECTED_REGION,
                "account_id": EXPECTED_ACCOUNT_ID,
            },
            "live_configuration": {
                "inbound_rule_count": 1,
                "outbound_rule_count": 1,
                "inbound_rules_empty": False,
                "outbound_rules_empty": False,
                "inbound_rules": [
                    {
                        "IpProtocol": "-1",
                        "UserIdGroupPairs": [
                            {
                                "UserId": EXPECTED_ACCOUNT_ID,
                                "GroupId": EXPECTED_SECURITY_GROUP_ID,
                            }
                        ],
                    }
                ],
                "outbound_rules": [
                    {
                        "IpProtocol": "-1",
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    }
                ],
            },
            "evidence_source": (
                "aws securityhub get-findings; "
                "aws ec2 describe-security-groups"
            ),
            "read_only": True,
            "execution_allowed": False,
            "error": None,
        }

    def make_proposal(
        self,
        findings=None,
        inventory=None,
        catalog=None,
        verification=None,
    ):
        return build_proposal(
            deepcopy(self.findings if findings is None else findings),
            deepcopy(self.inventory if inventory is None else inventory),
            deepcopy(self.catalog if catalog is None else catalog),
            deepcopy(
                self.verification
                if verification is None
                else verification
            ),
        )

    def test_fresh_live_evidence_generates_safe_draft(self):
        proposal = self.make_proposal()

        self.assertFalse(proposal["test_fixture"])
        self.assertEqual(proposal["evidence_status"], "LIVE_VERIFIED")
        self.assertEqual(proposal["proposal_status"], "DRAFT")
        self.assertEqual(
            proposal["remediation_decision"]["decision"],
            "REMEDIATION_REVIEW_REQUIRED",
        )
        self.assertTrue(proposal["governance"]["approval_required"])
        self.assertEqual(
            proposal["governance"]["approval_status"], "PENDING"
        )
        self.assertFalse(proposal["governance"]["execution_allowed"])
        self.assertEqual(proposal["execution_status"], "NOT_EXECUTED")

    def test_stale_verification_evidence_is_rejected(self):
        verification = deepcopy(self.verification)
        verification["checked_at"] = (
            datetime.now(timezone.utc)
            - timedelta(seconds=MAX_EVIDENCE_AGE_SECONDS + 60)
        ).isoformat()

        proposal = self.make_proposal(verification=verification)

        self.assertEqual(
            proposal["evidence_status"], "LIVE_EVIDENCE_REJECTED"
        )
        self.assertEqual(
            proposal["remediation_decision"]["decision"],
            "HOLD_FOR_REVIEW",
        )
        self.assertIn(
            "Live verification evidence is stale.",
            proposal["evidence"]["verification_issues"],
        )
        self.assertFalse(proposal["governance"]["execution_allowed"])
        self.assertEqual(proposal["execution_status"], "NOT_EXECUTED")

    def test_wrong_finding_id_is_rejected(self):
        findings = deepcopy(self.findings)
        findings["findings"][0]["finding_id"] = (
            "arn:aws:securityhub:wrong-finding"
        )

        with self.assertRaisesRegex(
            ValueError,
            "Expected exactly one stored EC2.2 finding",
        ):
            self.make_proposal(findings=findings)

    def test_verification_resource_arn_mismatch_is_rejected(self):
        verification = deepcopy(self.verification)
        verification["resource"]["resource_id"] = (
            "arn:aws:ec2:us-east-1:665808487090:"
            "security-group/sg-wrong"
        )

        proposal = self.make_proposal(verification=verification)

        self.assertEqual(
            proposal["evidence_status"], "LIVE_EVIDENCE_REJECTED"
        )
        self.assertIn(
            "Verification resource ARN does not match.",
            proposal["evidence"]["verification_issues"],
        )
        self.assertFalse(proposal["governance"]["execution_allowed"])

    def test_read_only_flag_must_be_true(self):
        verification = deepcopy(self.verification)
        verification["read_only"] = False

        proposal = self.make_proposal(verification=verification)

        self.assertEqual(
            proposal["evidence_status"], "LIVE_EVIDENCE_REJECTED"
        )
        self.assertIn(
            "Verification is not explicitly marked read-only.",
            proposal["evidence"]["verification_issues"],
        )
        self.assertFalse(proposal["governance"]["execution_allowed"])

    def test_execution_allowed_flag_must_be_false(self):
        verification = deepcopy(self.verification)
        verification["execution_allowed"] = True

        proposal = self.make_proposal(verification=verification)

        self.assertEqual(
            proposal["evidence_status"], "LIVE_EVIDENCE_REJECTED"
        )
        self.assertIn(
            "Verification does not explicitly disable execution.",
            proposal["evidence"]["verification_issues"],
        )
        self.assertFalse(proposal["governance"]["execution_allowed"])

    def test_unknown_management_mechanism_adds_prerequisite(self):
        proposal = self.make_proposal()

        management = proposal["management_context"]
        prerequisites = proposal["risk_assessment"][
            "unresolved_prerequisites"
        ]

        self.assertEqual(management["management_mechanism"], "unknown")
        self.assertIn(
            "Management mechanism is unknown; identify and verify it.",
            prerequisites,
        )
        self.assertFalse(proposal["governance"]["execution_allowed"])
        self.assertEqual(proposal["execution_status"], "NOT_EXECUTED")

    def test_blank_management_mechanism_adds_prerequisite(self):
        for value in ("", "   "):
            with self.subTest(management_mechanism=repr(value)):
                inventory = deepcopy(self.inventory)
                inventory["resources"][0]["management_mechanism"] = value

                proposal = self.make_proposal(inventory=inventory)

                prerequisites = proposal["risk_assessment"][
                    "unresolved_prerequisites"
                ]

                self.assertIn(
                    "Management mechanism is unknown; identify and verify it.",
                    prerequisites,
                )
                self.assertFalse(
                    proposal["governance"]["execution_allowed"]
                )
                self.assertEqual(
                    proposal["execution_status"], "NOT_EXECUTED"
                )

    def test_inventory_must_have_exactly_one_resource_match(self):
        inventory = deepcopy(self.inventory)
        inventory["resources"].append(
            deepcopy(inventory["resources"][0])
        )

        with self.assertRaisesRegex(
            ValueError,
            "Expected exactly one inventory match",
        ):
            self.make_proposal(inventory=inventory)

    def test_compliant_verification_does_not_authorize_execution(self):
        verification = deepcopy(self.verification)
        verification["status"] = "COMPLIANT"
        verification["live_configuration"] = {
            "inbound_rule_count": 0,
            "outbound_rule_count": 0,
            "inbound_rules_empty": True,
            "outbound_rules_empty": True,
            "inbound_rules": [],
            "outbound_rules": [],
        }

        proposal = self.make_proposal(verification=verification)

        self.assertEqual(proposal["evidence_status"], "LIVE_VERIFIED")
        self.assertEqual(
            proposal["remediation_decision"]["decision"],
            "NO_ACTION_CURRENT_CONFIGURATION_COMPLIANT",
        )
        self.assertEqual(proposal["proposal_status"], "REVIEW_REQUIRED")
        self.assertFalse(proposal["governance"]["execution_allowed"])
        self.assertEqual(proposal["execution_status"], "NOT_EXECUTED")


if __name__ == "__main__":
    unittest.main()