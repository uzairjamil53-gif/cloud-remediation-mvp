import unittest

from findings.match_inventory import (
    canonical_resource_id,
    normalize_resource_type,
)


class ResourceMatchingTests(unittest.TestCase):
    def test_iam_role_type_is_normalized(self):
        self.assertEqual(
            normalize_resource_type("AwsIamRole"),
            "AWS::IAM::Role",
        )

    def test_athena_workgroup_type_is_normalized(self):
        self.assertEqual(
            normalize_resource_type("AwsAthenaWorkGroup"),
            "AWS::Athena::WorkGroup",
        )

    def test_s3_bucket_arn_is_canonicalized(self):
        self.assertEqual(
            canonical_resource_id(
                "AWS::S3::Bucket",
                "arn:aws:s3:::example-bucket",
            ),
            "example-bucket",
        )

    def test_iam_role_arn_is_preserved(self):
        role_arn = (
            "arn:aws:iam::123456789012:role/"
            "aws-service-role/example.amazonaws.com/ExampleRole"
        )

        self.assertEqual(
            canonical_resource_id("AWS::IAM::Role", role_arn),
            role_arn,
        )

    def test_vpc_block_public_access_type_is_preserved(self):
        resource_type = "AwsEc2VPCBlockPublicAccessOptions"

        self.assertEqual(
            normalize_resource_type(resource_type),
            resource_type,
        )

    def test_snapshot_block_public_access_type_is_preserved(self):
        resource_type = "AwsEc2SnapshotBlockPublicAccess"

        self.assertEqual(
            normalize_resource_type(resource_type),
            resource_type,
        )

    def test_vpc_block_public_access_arn_is_preserved(self):
        resource_id = (
            "arn:aws:ec2:us-east-1:123456789012:"
            "vpcblockpublicaccessoptions/123456789012"
        )

        self.assertEqual(
            canonical_resource_id(
                "AwsEc2VPCBlockPublicAccessOptions",
                resource_id,
            ),
            resource_id,
        )

    def test_snapshot_block_public_access_arn_is_preserved(self):
        resource_id = (
            "arn:aws:ec2:us-east-1:123456789012:"
            "snapshotblockpublicaccess/123456789012"
        )

        self.assertEqual(
            canonical_resource_id(
                "AwsEc2SnapshotBlockPublicAccess",
                resource_id,
            ),
            resource_id,
        )


if __name__ == "__main__":
    unittest.main()