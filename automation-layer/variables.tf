# automation-layer/variables.tf

variable "aws_region" {
  description = "AWS region where resources will be deployed."
  type        = string
}

variable "tags" {
  description = "A map of tags to apply to all taggable resources created by this automation layer."
  type        = map(string)
  default     = {}
}

variable "prefix" {
  description = "Prefix for naming resources created by this automation layer (e.g., 'slack-bastion')."
  type        = string
  default     = "slack-bastion-automation"
}

variable "slack_signing_secret_arn" {
  description = "ARN of the AWS Secrets Manager secret containing the Slack App's Signing Secret."
  type        = string
  # No default - this must be provided.
}

variable "slack_bot_token_secret_arn" {
  description = "ARN of the AWS Secrets Manager secret containing the Slack App's Bot User OAuth Token (required for posting messages beyond the initial response)."
  type        = string
  # No default - this must be provided.
}

variable "authorized_slack_user_ids_ssm_param_name" {
  description = "Name for the SSM Parameter Store parameter (StringList) storing authorized Slack User IDs."
  type        = string
  default     = "/slack-bastion/authorized-users"
}

variable "terraform_state_bucket_name" {
  description = "Name for the S3 bucket to store Terraform state for the automation layer and bastion sessions. Must be globally unique."
  type        = string
  # No default - this should be unique and provided by the user.
}

variable "bastion_session_default_lifetime_minutes" {
  description = "Default lifetime (in minutes) for a bastion session before it's automatically destroyed."
  type        = number
  default     = 240 # 4 hours
}

# --- Variables needed by the underlying Bastion Module ---
# These are passed through to the bastion module when invoked by the Request Lambda.

variable "bastion_module_source" {
  description = "Source path or URL for the terraform-aws-secure-bastion module."
  type        = string
  default     = "../" # Assumes the bastion module is one directory up
}

variable "bastion_vpc_id" {
  description = "VPC ID where the bastion instances will be deployed."
  type        = string
  # No default - must be provided.
}

variable "bastion_subnet_id" {
  description = "Subnet ID where the bastion instances will be deployed. Should ideally be a private subnet with VPC endpoints."
  type        = string
  # No default - must be provided.
}

variable "bastion_instance_type" {
  description = "Default EC2 instance type for the bastion hosts."
  type        = string
  default     = "t3.micro"
}

variable "bastion_allowed_ssm_principal_arns" {
  description = "List of baseline IAM Role/User ARNs allowed to start SSM sessions. The Request Lambda might add specific user roles dynamically if needed."
  type        = list(string)
  default     = []
}

variable "bastion_log_s3_bucket_name" {
  description = "Optional: Name of an existing S3 bucket for bastion session logs. If null, the bastion module creates one."
  type        = string
  default     = null
}

variable "bastion_log_cloudwatch_group_name" {
  description = "Optional: Name of an existing CloudWatch Log Group for bastion session logs. If null, the bastion module creates one."
  type        = string
  default     = null
}

# --- VPC Configuration for Lambda Functions ---

variable "lambda_subnet_ids" {
  description = "List of subnet IDs in your VPC for the Lambda functions to run in. Required if using VPC endpoints."
  type        = list(string)
  default     = null # Set to null to run outside VPC by default
}

variable "lambda_security_group_ids" {
  description = "List of security group IDs to associate with the Lambda functions when running in a VPC."
  type        = list(string)
  default     = null # Set to null to use default SG if running outside VPC
}
