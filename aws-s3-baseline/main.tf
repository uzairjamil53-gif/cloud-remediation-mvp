terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }

    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

provider "aws" {
  region              = "us-east-1"
  allowed_account_ids = ["665808487090"]
}

data "aws_caller_identity" "current" {}

resource "random_id" "suffix" {
  byte_length = 4
}

resource "aws_s3_bucket" "test" {
  bucket = "cloud-remediation-mvp-${random_id.suffix.hex}"

  tags = {
    Project     = "CloudRemediationMVP"
    Environment = "Development"
    ManagedBy   = "Terraform"
    Purpose     = "SecurityRemediationTest"
  }
}

resource "aws_s3_bucket_public_access_block" "test" {
  bucket = aws_s3_bucket.test.id

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "test" {
  bucket = aws_s3_bucket.test.id

  versioning_configuration {
    status = "Enabled"
  }
}
resource "aws_s3_bucket_lifecycle_configuration" "test" {
  bucket = aws_s3_bucket.test.id

  rule {
    id     = "abort-incomplete-multipart-uploads"
    status = "Enabled"

    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "test" {
  bucket = aws_s3_bucket.test.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

output "aws_account_id" {
  description = "AWS account managing this resource"
  value       = data.aws_caller_identity.current.account_id
}

output "aws_region" {
  description = "AWS region used by this project"
  value       = "us-east-1"
}

output "test_bucket_name" {
  description = "Name of the private S3 test bucket"
  value       = aws_s3_bucket.test.bucket
}


# Dedicated S3 server access logging destination.
resource "aws_s3_bucket" "logging" {
  bucket = "cloud-remediation-mvp-logs-${random_id.suffix.hex}"

  tags = {
    Project     = "CloudRemediationMVP"
    Environment = "Development"
    ManagedBy   = "Terraform"
    Purpose     = "ServerAccessLogging"
  }
}

# Keep the logging bucket private.
resource "aws_s3_bucket_public_access_block" "logging" {
  bucket = aws_s3_bucket.logging.id

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

# Disable ACLs and enforce bucket ownership.
resource "aws_s3_bucket_ownership_controls" "logging" {
  bucket = aws_s3_bucket.logging.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# Use SSE-S3 encryption for compatibility with S3 log delivery.
resource "aws_s3_bucket_server_side_encryption_configuration" "logging" {
  bucket = aws_s3_bucket.logging.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Permit only the S3 logging service to deliver logs
# originating from our specific source bucket.
resource "aws_s3_bucket_policy" "logging" {
  bucket = aws_s3_bucket.logging.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowS3ServerAccessLogDelivery"
        Effect = "Allow"

        Principal = {
          Service = "logging.s3.amazonaws.com"
        }

        Action = [
          "s3:PutObject"
        ]

        Resource = "${aws_s3_bucket.logging.arn}/${aws_s3_bucket.test.bucket}/*"

        Condition = {
          ArnLike = {
            "aws:SourceArn" = aws_s3_bucket.test.arn
          }

          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })
}

# Enable server access logging on the existing source bucket.
resource "aws_s3_bucket_logging" "test" {
  bucket        = aws_s3_bucket.test.id
  target_bucket = aws_s3_bucket.logging.id
  target_prefix = "${aws_s3_bucket.test.bucket}/"

  depends_on = [
    aws_s3_bucket_policy.logging
  ]
}

output "logging_bucket_name" {
  description = "Dedicated S3 server access logging destination"
  value       = aws_s3_bucket.logging.bucket
}

resource "aws_s3_bucket_lifecycle_configuration" "logging" {
  bucket = aws_s3_bucket.logging.id

  rule {
    id     = "expire-server-access-logs"
    status = "Enabled"

    filter {
      prefix = "${aws_s3_bucket.test.bucket}/"
    }

    expiration {
      days = 30
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}


# MVP remediation: Require TLS for all source bucket requests.
resource "aws_s3_bucket_policy" "test" {
  bucket = aws_s3_bucket.test.id

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"

        Resource = [
          aws_s3_bucket.test.arn,
          "${aws_s3_bucket.test.arn}/*"
        ]

        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}
