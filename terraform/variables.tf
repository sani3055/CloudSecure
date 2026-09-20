variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "ap-south-1"
}

variable "github_repo" {
  description = "GitHub repository for OIDC (org/repo)"
  type        = string
  default     = "sani3055/CloudSecure"
}

variable "alert_email" {
  description = "Email address for SNS alerts. If empty, no email subscription is created."
  type        = string
  default     = ""
}
