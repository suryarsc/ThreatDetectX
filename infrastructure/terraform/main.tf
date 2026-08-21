terraform {
  required_version = ">= 1.3.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }
}

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = var.tags
  }
}

# Random suffix to guarantee unique S3 bucket name
resource "random_string" "bucket_suffix" {
  length  = 6
  special = false
  upper   = false
}

# S3 Bucket for Security Logs (CloudTrail, Zeek, Network Telemetry)
resource "aws_s3_bucket" "security_logs" {
  bucket        = "${var.s3_bucket_prefix}-${var.environment}-${random_string.bucket_suffix.result}"
  force_destroy = true
}

# Bucket Ownership Controls
resource "aws_s3_bucket_ownership_controls" "security_logs" {
  bucket = aws_s3_bucket.security_logs.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# Server-Side Encryption (AES256 default)
resource "aws_s3_bucket_server_side_encryption_configuration" "security_logs_encryption" {
  bucket = aws_s3_bucket.security_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Block all public access for security compliance
resource "aws_s3_bucket_public_access_block" "security_logs_pab" {
  bucket = aws_s3_bucket.security_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# S3 Lifecycle Rule to transition older logs to Glacier / Infrequent Access
resource "aws_s3_bucket_lifecycle_configuration" "security_logs_lifecycle" {
  bucket = aws_s3_bucket.security_logs.id

  rule {
    id     = "archive-old-logs"
    status = "Enabled"

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    expiration {
      days = 365
    }
  }
}

# IAM Role for ThreatDetectX Backend & Ingestion Engine
resource "aws_iam_role" "tdx_backend_role" {
  name = "${var.project_name}-backend-role-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = [
            "ec2.amazonaws.com",
            "lambda.amazonaws.com"
          ]
        }
      }
    ]
  })
}

# IAM Policy with Least Privilege for S3 Ingestion
resource "aws_iam_policy" "tdx_s3_policy" {
  name        = "${var.project_name}-s3-policy-${var.environment}"
  description = "Allows ThreatDetectX backend to upload, list, and retrieve security logs from S3"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "S3LogBucketAccess"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.security_logs.arn,
          "${aws_s3_bucket.security_logs.arn}/*"
        ]
      }
    ]
  })
}

# Attach IAM Policy to Role
resource "aws_iam_role_policy_attachment" "tdx_s3_attach" {
  role       = aws_iam_role.tdx_backend_role.name
  policy_arn = aws_iam_policy.tdx_s3_policy.arn
}
