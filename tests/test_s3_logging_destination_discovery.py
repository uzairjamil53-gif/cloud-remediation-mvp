import unittest
from unittest.mock import patch

from remediation.discover_s3_logging_destinations import discover


class TestS3LoggingDestinationDiscovery(unittest.TestCase):

    @patch(
        "remediation.discover_s3_logging_destinations.list_buckets"
    )
    def test_aws_list_failure_returns_unknown(self, mock_list):
        mock_list.return_value = (None, "AccessDenied")

        result = discover()

        self.assertEqual(result["status"], "UNKNOWN")
        self.assertEqual(result["error"], "AccessDenied")
        self.assertFalse(result["execution_allowed"])
        self.assertEqual(result["candidates"], [])

    @patch(
        "remediation.discover_s3_logging_destinations.get_bucket_logging"
    )
    @patch(
        "remediation.discover_s3_logging_destinations.get_bucket_location"
    )
    @patch(
        "remediation.discover_s3_logging_destinations.list_buckets"
    )
    def test_source_bucket_is_not_approved(
        self, mock_list, mock_location, mock_logging
    ):
        mock_list.return_value = (
            {"Buckets": [{"Name": "cloud-remediation-mvp-848f82dd"}]},
            None,
        )
        mock_location.return_value = ("us-east-1", None)
        mock_logging.return_value = (
            {"enabled": False, "target_bucket": None, "target_prefix": ""},
            None,
        )

        result = discover()
        candidate = result["candidates"][0]

        self.assertEqual(result["status"], "DISCOVERY_COMPLETE")
        self.assertFalse(candidate["approved_destination"])
        self.assertEqual(
            candidate["candidate_status"], "REQUIRES_MANUAL_REVIEW"
        )
        self.assertTrue(
            any("MVP test/source bucket" in issue
                for issue in candidate["issues"])
        )
        self.assertFalse(result["execution_allowed"])

    @patch(
        "remediation.discover_s3_logging_destinations.get_bucket_logging"
    )
    @patch(
        "remediation.discover_s3_logging_destinations.get_bucket_location"
    )
    @patch(
        "remediation.discover_s3_logging_destinations.list_buckets"
    )
    def test_bucket_in_another_region_is_flagged(
        self, mock_list, mock_location, mock_logging
    ):
        mock_list.return_value = (
            {"Buckets": [{"Name": "another-existing-bucket"}]},
            None,
        )
        mock_location.return_value = ("us-west-2", None)
        mock_logging.return_value = (
            {"enabled": False, "target_bucket": None, "target_prefix": ""},
            None,
        )

        result = discover()
        candidate = result["candidates"][0]

        self.assertIn(
            "Bucket is not in the source bucket's region.",
            candidate["issues"],
        )
        self.assertFalse(candidate["approved_destination"])

    @patch(
        "remediation.discover_s3_logging_destinations.get_bucket_logging"
    )
    @patch(
        "remediation.discover_s3_logging_destinations.get_bucket_location"
    )
    @patch(
        "remediation.discover_s3_logging_destinations.list_buckets"
    )
    def test_unknown_region_is_not_treated_as_verified(
        self, mock_list, mock_location, mock_logging
    ):
        mock_list.return_value = (
            {"Buckets": [{"Name": "another-existing-bucket"}]},
            None,
        )
        mock_location.return_value = (None, "AccessDenied")
        mock_logging.return_value = (
            {"enabled": False, "target_bucket": None, "target_prefix": ""},
            None,
        )

        result = discover()
        candidate = result["candidates"][0]

        self.assertFalse(candidate["region_verified"])
        self.assertIn("Region could not be verified.", candidate["issues"])
        self.assertFalse(candidate["approved_destination"])

    @patch(
        "remediation.discover_s3_logging_destinations.get_bucket_logging"
    )
    @patch(
        "remediation.discover_s3_logging_destinations.get_bucket_location"
    )
    @patch(
        "remediation.discover_s3_logging_destinations.list_buckets"
    )
    def test_logging_error_is_recorded(
        self, mock_list, mock_location, mock_logging
    ):
        mock_list.return_value = (
            {"Buckets": [{"Name": "another-existing-bucket"}]},
            None,
        )
        mock_location.return_value = ("us-east-1", None)
        mock_logging.return_value = (None, "AccessDenied")

        result = discover()
        candidate = result["candidates"][0]

        self.assertFalse(candidate["logging_verified"])
        self.assertIn(
            "Existing logging configuration could not be verified.",
            candidate["issues"],
        )
        self.assertFalse(candidate["approved_destination"])

    @patch(
        "remediation.discover_s3_logging_destinations.get_bucket_logging"
    )
    @patch(
        "remediation.discover_s3_logging_destinations.get_bucket_location"
    )
    @patch(
        "remediation.discover_s3_logging_destinations.list_buckets"
    )
    def test_no_candidate_is_automatically_approved(
        self, mock_list, mock_location, mock_logging
    ):
        mock_list.return_value = (
            {"Buckets": [{"Name": "possible-destination"}]},
            None,
        )
        mock_location.return_value = ("us-east-1", None)
        mock_logging.return_value = (
            {"enabled": False, "target_bucket": None, "target_prefix": ""},
            None,
        )

        result = discover()

        self.assertEqual(result["bucket_count"], 1)
        self.assertTrue(
            all(
                not candidate["approved_destination"]
                for candidate in result["candidates"]
            )
        )
        self.assertFalse(result["execution_allowed"])


if __name__ == "__main__":
    unittest.main()
