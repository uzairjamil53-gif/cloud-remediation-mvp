import unittest
from unittest.mock import patch
from inventory.inventory import (
    apply_terraform_management,
    collect_s3_buckets,
    collect_vpc_block_public_access,
    collect_snapshot_block_public_access,
)


class InventoryTests(unittest.TestCase):
    @patch("inventory.inventory.get_bucket_tags", return_value=[])
    @patch(
        "inventory.inventory.get_bucket_region",
        return_value="us-east-1",
    )
    def test_terraform_managed_bucket_is_confirmed(
        self, mock_region, mock_tags
    ):
        buckets = [{"Name": "managed-bucket"}]


        resources = collect_s3_buckets(
            "123456789012",
            buckets,
            {
                ("AWS::S3::Bucket", "managed-bucket"):
                    "aws_s3_bucket.test"
            },
        )

        resource = resources[0]

        self.assertIs(resource["managed_by_terraform"], True)
        self.assertEqual(resource["management_mechanism"], "terraform")
        self.assertEqual(
            resource["terraform_management_status"],
            "confirmed_in_current_state",
        )

    @patch("inventory.inventory.get_bucket_tags", return_value=[])
    @patch(
        "inventory.inventory.get_bucket_region",
        return_value="us-east-1",
    )
    def test_unconfirmed_bucket_management_is_unknown(
        self, mock_region, mock_tags
    ):
        buckets = [{"Name": "unconfirmed-bucket"}]


        resources = collect_s3_buckets(
            "123456789012",
            buckets,
            {},
        )

        resource = resources[0]

        self.assertIsNone(resource["managed_by_terraform"])
        self.assertEqual(resource["management_mechanism"], "unknown")
        self.assertEqual(
            resource["terraform_management_status"],
            "not_found_in_current_state",
        )


    def test_terraform_management_is_confirmed_by_resource_identity(self):
        resource = {
            "resource_type": "AWS::EC2::VPC",
            "resource_id": "vpc-12345678",
            "resource_name": "vpc-12345678",
        }

        identities = {
            ("AWS::EC2::VPC", "vpc-12345678"):
                "aws_vpc.main"
        }

        result = apply_terraform_management(resource, identities)

        self.assertIs(result["managed_by_terraform"], True)
        self.assertEqual(result["management_mechanism"], "terraform")
        self.assertEqual(
            result["terraform_management_status"],
            "confirmed_in_current_state",
        )
        self.assertEqual(
            result["terraform_resource_address"],
            "aws_vpc.main",
        )

    def test_athena_workgroup_matches_terraform_state_by_name(self):
        resource = {
            "resource_type": "AWS::Athena::WorkGroup",
            "resource_id": (
                "arn:aws:athena:us-east-1:123456789012:"
                "workgroup/analytics"
            ),
            "resource_name": "analytics",
        }

        identities = {
            ("AWS::Athena::WorkGroup", "analytics"):
                "aws_athena_workgroup.analytics"
        }

        result = apply_terraform_management(resource, identities)

        self.assertIs(result["managed_by_terraform"], True)
        self.assertEqual(
            result["management_mechanism"],
            "terraform",
        )
        self.assertEqual(
            result["terraform_management_status"],
            "confirmed_in_current_state",
        )
        self.assertEqual(
            result["terraform_resource_address"],
            "aws_athena_workgroup.analytics",
        )

    def test_missing_terraform_identity_remains_unknown(self):
        resource = {
            "resource_type": "AWS::EC2::VPC",
            "resource_id": "vpc-87654321",
            "resource_name": "vpc-87654321",
        }

        result = apply_terraform_management(resource, {})

        self.assertIsNone(result["managed_by_terraform"])
        self.assertEqual(result["management_mechanism"], "unknown")
        self.assertEqual(
            result["terraform_management_status"],
            "not_found_in_current_state",
        )
        self.assertIsNone(result["terraform_resource_address"])

    @patch("inventory.inventory.aws_json")

    def test_vpc_block_public_access_settings_are_inventoried(
        self, mock_aws_json
    ):
        mock_aws_json.return_value = {
            "VpcBlockPublicAccessOptions": {
                "AwsAccountId": "123456789012",
                "AwsRegion": "us-east-1",
                "State": "default-state",
                "InternetGatewayBlockMode": "off",
                "Reason": "Default State",
                "ManagedBy": "account",
                "ExclusionsAllowed": "allowed",
            }
        }

        resources = collect_vpc_block_public_access("123456789012")

        self.assertEqual(len(resources), 1)
        resource = resources[0]

        self.assertEqual(
            resource["resource_type"],
            "AwsEc2VPCBlockPublicAccessOptions",
        )
        self.assertEqual(
            resource["resource_id"],
            "arn:aws:ec2:us-east-1:123456789012:"
            "vpcblockpublicaccessoptions/123456789012",
        )
        self.assertEqual(resource["internet_gateway_block_mode"], "off")
        self.assertEqual(resource["management_mechanism"],
                         "aws_account_configuration")
        mock_aws_json.assert_called_once()

    @patch("inventory.inventory.aws_json")
    def test_snapshot_block_public_access_settings_are_inventoried(
        self, mock_aws_json
    ):
        mock_aws_json.return_value = {
            "State": "unblocked",
            "ManagedBy": "account",
        }

        resources = collect_snapshot_block_public_access("123456789012")

        self.assertEqual(len(resources), 1)
        resource = resources[0]

        self.assertEqual(
            resource["resource_type"],
            "AwsEc2SnapshotBlockPublicAccess",
        )
        self.assertEqual(
            resource["resource_id"],
            "arn:aws:ec2:us-east-1:123456789012:"
            "snapshotblockpublicaccess/123456789012",
        )
        self.assertEqual(resource["state"], "unblocked")
        self.assertEqual(resource["management_mechanism"],
                         "aws_account_configuration")
        mock_aws_json.assert_called_once()

if __name__ == "__main__":
    unittest.main()
