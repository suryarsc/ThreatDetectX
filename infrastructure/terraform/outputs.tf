output "s3_bucket_name" {
  description = "The name of the S3 bucket created for log ingestion"
  value       = aws_s3_bucket.security_logs.id
}

output "s3_bucket_arn" {
  description = "The ARN of the S3 bucket created for log ingestion"
  value       = aws_s3_bucket.security_logs.arn
}

output "iam_role_arn" {
  description = "The ARN of the IAM role for ThreatDetectX backend services"
  value       = aws_iam_role.tdx_backend_role.arn
}

output "iam_role_name" {
  description = "The name of the IAM role for ThreatDetectX backend services"
  value       = aws_iam_role.tdx_backend_role.name
}
