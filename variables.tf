# aws-secure-bastion-on-demand/variables.tf

variable "vpc_id" {
  description = "ID of the VPC where the bastion host will reside."
  type        = string
}

variable "subnet_id" {
  description = "ID of the Subnet for the bastion host. Should ideally be a private subnet if using VPC endpoints for SSM."
  type        = string
}

variable "instance_type" {
  description = "EC2 instance type for the bastion host."
  type        = string
  default     = "t3.micro"
}

variable "ami_id" {
  description = "Specific AMI ID to use for the bastion host. If null, the latest Amazon Linux 2023 AMI for the region will be used."
  type        = string
  default     = null # Will use data source to find latest AL2023
}

variable "bastion_name_prefix" {
  description = "Prefix for naming resources created by this module."
  type        = string
  default     = "aws-secure-bastion-on-demand" # Updated default
}

variable "session_log_s3_bucket_name" {
  description = "Name of an existing S3 bucket for storing SSM session logs. If null, a new bucket will be created."
  type        = string
  default     = null
}

variable "session_log_cloudwatch_group_name" {
  description = "Name of an existing CloudWatch Log Group for storing SSM session logs. If null, a new log group will be created."
  type        = string
  default     = null
}

variable "log_retention_days" {
  description = "Retention period in days for CloudWatch logs."
  type        = number
  default     = 90
}

variable "s3_log_retention_days" {
  description = "Retention period in days for S3 logs (via lifecycle rule)."
  type        = number
  default     = 365
}

variable "allowed_ssm_principal_arns" {
  description = "List of IAM Role/User ARNs allowed to start SSM sessions on this bastion host."
  type        = list(string)
}

variable "tags" {
  description = "A map of additional tags to apply to the resources."
  type        = map(string)
  default     = {}
}

variable "create_s3_bucket" {
  description = "Flag to control creation of the S3 bucket. Set to false if using an existing bucket specified in session_log_s3_bucket_name."
  type        = bool
  default     = true # Derived internally based on session_log_s3_bucket_name
}

variable "create_cloudwatch_log_group" {
  description = "Flag to control creation of the CloudWatch Log Group. Set to false if using an existing group specified in session_log_cloudwatch_group_name."
  type        = bool
  default     = true # Derived internally based on session_log_cloudwatch_group_name
}
