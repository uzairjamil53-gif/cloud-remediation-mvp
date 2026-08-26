import unittest

from inventory.inventory import extract_terraform_resource_identities


class TerraformStateTests(unittest.TestCase):
    def test_extracts_s3_bucket_identity(self):
        state = {
            "values": {
                "root_module": {
                    "resources": [
                        {
                            "address": "aws_s3_bucket.test",
                            "mode": "managed",
                            "type": "aws_s3_bucket",
                            "name": "test",
                            "values": {
                                "bucket": "example-bucket",
                                "id": "example-bucket",
                                "arn": "arn:aws:s3:::example-bucket",
                            },
                        }
                    ]
                }
            }
        }

        identities = extract_terraform_resource_identities(state)

        self.assertEqual(
            identities,
            {
                ("AWS::S3::Bucket", "example-bucket"): (
                    "aws_s3_bucket.test"
                )
            },
        )

    def test_extracts_supported_network_resource_identities(self):
        state = {
            "values": {
                "root_module": {
                    "resources": [
                        {
                            "address": "aws_vpc.main",
                            "mode": "managed",
                            "type": "aws_vpc",
                            "name": "main",
                            "values": {"id": "vpc-123"},
                        },
                        {
                            "address": "aws_security_group.main",
                            "mode": "managed",
                            "type": "aws_security_group",
                            "name": "main",
                            "values": {"id": "sg-123"},
                        },
                        {
                            "address": "aws_subnet.main",
                            "mode": "managed",
                            "type": "aws_subnet",
                            "name": "main",
                            "values": {"id": "subnet-123"},
                        },
                    ]
                }
            }
        }

        identities = extract_terraform_resource_identities(state)

        self.assertIn(
            ("AWS::EC2::VPC", "vpc-123"),
            identities,
        )
        self.assertIn(
            ("AWS::EC2::SecurityGroup", "sg-123"),
            identities,
        )
        self.assertIn(
            ("AWS::EC2::Subnet", "subnet-123"),
            identities,
        )

    def test_excludes_configuration_and_helper_resources(self):
        state = {
            "values": {
                "root_module": {
                    "resources": [
                        {
                            "address": "aws_s3_bucket.test",
                            "mode": "managed",
                            "type": "aws_s3_bucket",
                            "name": "test",
                            "values": {"bucket": "example-bucket"},
                        },
                        {
                            "address": (
                                "aws_s3_bucket_versioning.test"
                            ),
                            "mode": "managed",
                            "type": "aws_s3_bucket_versioning",
                            "name": "test",
                            "values": {
                                "bucket": "example-bucket",
                                "id": "example-bucket",
                            },
                        },
                        {
                            "address": "random_id.suffix",
                            "mode": "managed",
                            "type": "random_id",
                            "name": "suffix",
                            "values": {"id": "abc123"},
                        },
                        {
                            "address": "data.aws_caller_identity.current",
                            "mode": "data",
                            "type": "aws_caller_identity",
                            "name": "current",
                            "values": {"account_id": "123456789012"},
                        },
                    ]
                }
            }
        }

        identities = extract_terraform_resource_identities(state)

        self.assertEqual(
            identities,
            {
                ("AWS::S3::Bucket", "example-bucket"): (
                    "aws_s3_bucket.test"
                )
            },
        )

    def test_handles_missing_root_module(self):
        self.assertEqual(
            extract_terraform_resource_identities({}),
            {},
        )

    def test_walks_child_modules(self):
        state = {
            "values": {
                "root_module": {
                    "resources": [],
                    "child_modules": [
                        {
                            "resources": [
                                {
                                    "address": (
                                        "module.network.aws_vpc.main"
                                    ),
                                    "mode": "managed",
                                    "type": "aws_vpc",
                                    "name": "main",
                                    "values": {"id": "vpc-456"},
                                }
                            ],
                            "child_modules": [],
                        }
                    ],
                }
            }
        }

        identities = extract_terraform_resource_identities(state)

        self.assertEqual(
            identities[
                ("AWS::EC2::VPC", "vpc-456")
            ],
            "module.network.aws_vpc.main",
        )


if __name__ == "__main__":
    unittest.main()