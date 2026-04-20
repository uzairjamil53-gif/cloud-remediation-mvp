import unittest

from remediation.verify_s3_configuration import (
    evaluate_configuration,
)


DESIRED = {
    "block_public_acls": True,
    "ignore_public_acls": True,
    "block_public_policy": True,
    "restrict_public_buckets": True,
}

ALL_ENABLED = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}


class S3VerificationTests(unittest.TestCase):
    def test_all_settings_enabled_is_compliant(self):
        status, missing = evaluate_configuration(
            ALL_ENABLED, DESIRED
        )

        self.assertEqual(status, "COMPLIANT")
        self.assertEqual(missing, [])

    def test_disabled_setting_is_non_compliant(self):
        observed = dict(ALL_ENABLED)
        observed["BlockPublicPolicy"] = False

        status, missing = evaluate_configuration(
            observed, DESIRED
        )

        self.assertEqual(status, "NON_COMPLIANT")
        self.assertEqual(missing, [])

    def test_missing_setting_is_unknown(self):
        observed = dict(ALL_ENABLED)
        del observed["RestrictPublicBuckets"]

        status, missing = evaluate_configuration(
            observed, DESIRED
        )

        self.assertEqual(status, "UNKNOWN")
        self.assertEqual(missing, ["RestrictPublicBuckets"])


if __name__ == "__main__":
    unittest.main()
