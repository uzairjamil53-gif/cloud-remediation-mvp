import unittest
from unittest.mock import patch, Mock

from remediation.verify_s3_server_access_logging import (
    extract_bucket_name,
    read_logging_configuration,
)


class TestS3ServerAccessLoggingVerification(unittest.TestCase):

    def test_extract_bucket_name_from_arn(self):
        resource = {
            "resource_id": "arn:aws:s3:::cloud-remediation-mvp-848f82dd"
        }

        self.assertEqual(
            extract_bucket_name(resource),
            "cloud-remediation-mvp-848f82dd",
        )

    def test_extract_bucket_name_from_plain_name(self):
        resource = {"resource_id": "example-test-bucket"}

        self.assertEqual(
            extract_bucket_name(resource),
            "example-test-bucket",
        )

    def test_reject_bucket_resource_id_with_path(self):
        resource = {
            "resource_id": "arn:aws:s3:::example-test-bucket/some-key"
        }

        with self.assertRaises(ValueError):
            extract_bucket_name(resource)

    @patch("remediation.verify_s3_server_access_logging.subprocess.run")
    def test_empty_successful_response_means_no_logging_config(self, mock_run):
        mock_run.return_value = Mock(
            returncode=0,
            stdout="",
            stderr="",
        )

        configuration, error = read_logging_configuration(
            "example-test-bucket"
        )

        self.assertEqual(configuration, {})
        self.assertIsNone(error)

    @patch("remediation.verify_s3_server_access_logging.subprocess.run")
    def test_enabled_logging_configuration_is_returned(self, mock_run):
        mock_run.return_value = Mock(
            returncode=0,
            stdout=(
                '{"LoggingEnabled": {'
                '"TargetBucket": "approved-logs-bucket", '
                '"TargetPrefix": "access-logs/"}}'
            ),
            stderr="",
        )

        configuration, error = read_logging_configuration(
            "example-test-bucket"
        )

        self.assertIsNone(error)
        self.assertEqual(
            configuration["LoggingEnabled"]["TargetBucket"],
            "approved-logs-bucket",
        )
        self.assertEqual(
            configuration["LoggingEnabled"]["TargetPrefix"],
            "access-logs/",
        )

    @patch("remediation.verify_s3_server_access_logging.subprocess.run")
    def test_aws_cli_failure_returns_unknown_evidence(self, mock_run):
        mock_run.return_value = Mock(
            returncode=1,
            stdout="",
            stderr="AccessDenied",
        )

        configuration, error = read_logging_configuration(
            "example-test-bucket"
        )

        self.assertIsNone(configuration)
        self.assertEqual(error, "AccessDenied")

    @patch("remediation.verify_s3_server_access_logging.subprocess.run")
    def test_invalid_json_response_is_rejected(self, mock_run):
        mock_run.return_value = Mock(
            returncode=0,
            stdout="{invalid-json",
            stderr="",
        )

        configuration, error = read_logging_configuration(
            "example-test-bucket"
        )

        self.assertIsNone(configuration)
        self.assertEqual(
            error,
            "AWS CLI returned output that was not valid JSON.",
        )


if __name__ == "__main__":
    unittest.main()
