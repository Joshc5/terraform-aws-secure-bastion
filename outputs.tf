# aws-secure-bastion-on-demand/outputs.tf

output "bastion_instance_id" {
  description = "The ID of the EC2 instance created for the bastion host."
  value       = aws_instance.bastion_host.id
}

output "bastion_iam_role_arn" {
  description = "The ARN of the IAM role attached to the bastion host instance."
  value       = aws_iam_role.bastion_instance_role.arn
}

output "session_logs_s3_bucket_id" {
  description = "The ID (name) of the S3 bucket used for session logs. Only set if the bucket was created by this module."
  value       = local.create_s3_bucket ? aws_s3_bucket.session_logs[0].id : null
}

output "session_logs_cloudwatch_log_group_name" {
  description = "The name of the CloudWatch Log Group used for session logs. Only set if the log group was created by this module."
  value       = local.create_cloudwatch_log_group ? aws_cloudwatch_log_group.session_logs[0].name : null
}

output "ssm_start_session_policy_example_json" {
  description = "An example IAM policy JSON document that can be attached to user/role principals (e.g., AWS SSO roles) to grant them permission to start SSM sessions on this specific bastion instance. Remember to add MFA enforcement conditions if required."
  value       = data.aws_iam_policy_document.ssm_start_session_policy_example.json
}
