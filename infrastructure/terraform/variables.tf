variable "aws_region" {
  description = "The AWS region to deploy resources into"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment (e.g. dev, staging, prod)"
  type        = string
  default     = "dev"
}

variable "project_name" {
  description = "Name of the project"
  type        = string
  default     = "threatdetectx"
}

variable "s3_bucket_prefix" {
  description = "Prefix for the S3 security logs bucket"
  type        = string
  default     = "tdx-security-logs"
}

variable "tags" {
  description = "Default tags to apply to all resources"
  type        = map(string)
  default = {
    Project     = "ThreatDetectX"
    ManagedBy   = "Terraform"
    Environment = "dev"
    Component   = "Security-Ingestion"
  }
}
