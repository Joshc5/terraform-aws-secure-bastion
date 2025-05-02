# aws-secure-bastion-on-demand/main.tf

# This module provisions infrastructure for a secure, on-demand bastion host
# using AWS Systems Manager Session Manager for connectivity. This approach
# enhances security by eliminating the need for open SSH ports and leverages
# IAM for fine-grained access control and auditing.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.40" # Pinning to a recent minor version series (e.g., 5.40.x)
    }
  }
  # This module does not require a specific Terraform version itself,
  # but the automation layer using it might.
}

# --- Local Variables ---
# Used for conditional logic and simplifying resource references throughout the module.
locals {
  # Determine whether to create a new S3 bucket or use an existing one based on input variables.
  create_s3_bucket = var.session_log_s3_bucket_name == null && var.create_s3_bucket
  s3_bucket_name   = local.create_s3_bucket ? aws_s3_bucket.session_logs[0].id : var.session_log_s3_bucket_name
  s3_bucket_arn    = local.create_s3_bucket ? aws_s3_bucket.session_logs[0].arn : "arn:aws:s3:::${var.session_log_s3_bucket_name}" # Construct ARN for existing bucket

  # Determine whether to create a new CloudWatch log group or use an existing one.
  create_cloudwatch_log_group = var.session_log_cloudwatch_group_name == null && var.create_cloudwatch_log_group
  cloudwatch_log_group_name   = local.create_cloudwatch_log_group ? aws_cloudwatch_log_group.session_logs[0].name : var.session_log_cloudwatch_group_name
  cloudwatch_log_group_arn    = local.create_cloudwatch_log_group ? aws_cloudwatch_log_group.session_logs[0].arn : "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:${var.session_log_cloudwatch_group_name}:*" # Construct ARN for existing group

  # Merge default tags with user-provided tags. User tags override defaults if keys conflict.
  # Tags are crucial for cost allocation, identification, and automation (e.g., cleanup scripts).
  common_tags = merge(
    {
      "Name"        = "${var.bastion_name_prefix}-instance"
      # Updated Provisioner tag to reflect new module name
      "Provisioner" = "Terraform-AWSSecureBastionOnDemandModule"
    },
    var.tags
  )
}

# --- Data Sources ---
# Fetch information about the current AWS environment (region, account ID) and the desired AMI.
data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

# Find the latest Amazon Linux 2023 AMI if a specific one isn't provided via var.ami_id.
# Security Benefit: Using the latest vetted OS image helps ensure recent security patches are included.
data "aws_ami" "amazon_linux_2023" {
  count = var.ami_id == null ? 1 : 0 # Only perform this lookup if var.ami_id is not set.

  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-kernel-*-x86_64"] # Adjust filter as needed for AL2023
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# --- Logging Resources (Conditional Creation) ---
# These resources are created only if the user doesn't provide existing logging destinations.
# Secure Audit Trail: Centralized logging of session activity is crucial for security monitoring and compliance.

# Creates an S3 bucket for storing SSM session logs if one is not provided.
resource "aws_s3_bucket" "session_logs" {
  count = local.create_s3_bucket ? 1 : 0

  # Bucket name includes prefix, account ID, and region for uniqueness.
  bucket = "${var.bastion_name_prefix}-ssm-logs-${data.aws_caller_identity.current.account_id}-${data.aws_region.current.name}"
  tags   = local.common_tags
}

# Enforces server-side encryption (SSE-S3) for logs stored in the S3 bucket.
# Security Benefit: Protects log data at rest.
resource "aws_s3_bucket_server_side_encryption_configuration" "session_logs_sse" {
  count = local.create_s3_bucket ? 1 : 0

  bucket = aws_s3_bucket.session_logs[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256" # Uses AES256 encryption managed by S3.
    }
  }
}

# Blocks all public access to the S3 bucket.
# Security Benefit: Prevents accidental exposure of potentially sensitive session logs.
resource "aws_s3_bucket_public_access_block" "session_logs_public_access" {
  count = local.create_s3_bucket ? 1 : 0

  bucket                  = aws_s3_bucket.session_logs[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Configures a lifecycle rule to automatically delete old logs from the S3 bucket.
# Compliance/Cost Benefit: Manages storage costs and adheres to data retention policies.
resource "aws_s3_bucket_lifecycle_configuration" "session_logs_lifecycle" {
  count = local.create_s3_bucket ? 1 : 0

  bucket = aws_s3_bucket.session_logs[0].id

  rule {
    id     = "log-retention"
    status = "Enabled"

    expiration {
      days = var.s3_log_retention_days
    }
  }
}

# Attaches a policy to the S3 bucket (either created or existing) allowing the SSM service
# to check bucket permissions and deliver session logs.
# Security Benefit: Ensures only the SSM service principal can write logs, scoped to this bucket.
resource "aws_s3_bucket_policy" "session_logs_policy" {
  # Apply policy whether bucket is created or existing.
  bucket = local.s3_bucket_name

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid    = "SSMLoggingBucketPermissionsCheck",
        Effect = "Allow",
        Principal = {
          Service = "ssm.amazonaws.com"
        },
        Action   = "s3:GetBucketAcl",
        Resource = local.s3_bucket_arn
      },
      {
        Sid    = "SSMLoggingBucketDelivery",
        Effect = "Allow",
        Principal = {
          Service = "ssm.amazonaws.com"
        },
        Action   = "s3:PutObject",
        Resource = "${local.s3_bucket_arn}/*",
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })

  # Explicit dependency to prevent race conditions if the bucket is created by this module.
  depends_on = [aws_s3_bucket.session_logs]
}

# Creates a CloudWatch Log Group for storing SSM session logs if one is not provided.
# Provides an alternative/additional logging destination to S3.
resource "aws_cloudwatch_log_group" "session_logs" {
  count = local.create_cloudwatch_log_group ? 1 : 0

  # Log group name includes prefix for easier identification.
  name              = "${var.bastion_name_prefix}-ssm-session-logs"
  retention_in_days = var.log_retention_days
  tags              = local.common_tags
}

# --- IAM Role and Policy for EC2 Instance ---
# Defines the permissions the bastion host EC2 instance will have.
# Security Principle: Least Privilege - Grant only necessary permissions.

# Creates the IAM Role that the EC2 instance will assume.
resource "aws_iam_role" "bastion_instance_role" {
  # Role name includes prefix for identification.
  name               = "${var.bastion_name_prefix}-instance-role"
  # Trust policy allows the EC2 service to assume this role.
  assume_role_policy = jsonencode({
    Version   = "2012-10-17",
    Statement = [
      {
        Action    = "sts:AssumeRole",
        Effect    = "Allow",
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
  tags = local.common_tags
}

# Attaches the AWS managed policy required for the SSM agent to function.
# This policy grants permissions for the agent to communicate with the SSM service.
resource "aws_iam_role_policy_attachment" "ssm_core_policy" {
  role       = aws_iam_role.bastion_instance_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# Creates an inline policy granting permissions to write logs to S3 and CloudWatch.
# Security Principle: Scoped Permissions - Resources are explicitly defined using local variables.
resource "aws_iam_role_policy" "logging_policy" {
  # Policy name includes prefix.
  name = "${var.bastion_name_prefix}-logging-policy"
  role = aws_iam_role.bastion_instance_role.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "s3:PutObject"
        ],
        Resource = "${local.s3_bucket_arn}/*" # Grant write to the specific bucket/prefix
      },
      {
        Effect = "Allow",
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams"
        ],
        Resource = "${local.cloudwatch_log_group_arn}" # Grant write to the specific log group
      }
    ]
  })
}

# Creates an IAM Instance Profile to associate the IAM Role with the EC2 instance.
resource "aws_iam_instance_profile" "bastion_instance_profile" {
  # Instance profile name includes prefix.
  name = "${var.bastion_name_prefix}-instance-profile"
  role = aws_iam_role.bastion_instance_role.name
  tags = local.common_tags
}

# --- Security Group ---
# Defines network access rules for the bastion host.

resource "aws_security_group" "bastion_sg" {
  # Security group name includes prefix.
  name        = "${var.bastion_name_prefix}-sg"
  description = "Security group for the on-demand bastion host. Allows outbound HTTPS for SSM agent."
  vpc_id      = var.vpc_id

  # Security Benefit: No inbound rules are defined, significantly reducing the attack surface.
  # Access is established via SSM Session Manager, which uses outbound connections initiated by the SSM agent.
  # If VPC Endpoints for SSM are used, the instance doesn't even need outbound internet access, only access to the endpoints.

  # Allows outbound HTTPS traffic.
  # Required for the SSM agent to communicate with the SSM service endpoints.
  # Also allows for OS patching and updates if needed. Consider restricting cidr_blocks if VPC endpoints are used and internet access is not required.
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Allows SSM agent communication and OS patching
    description = "Allow outbound HTTPS for SSM agent and patching"
  }

  tags = local.common_tags
}

# --- EC2 Instance ---
# The actual bastion host compute resource.

resource "aws_instance" "bastion_host" {
  # Use the specified AMI or the latest AL2023 found by the data source.
  ami           = var.ami_id == null ? data.aws_ami.amazon_linux_2023[0].id : var.ami_id
  instance_type = var.instance_type
  subnet_id     = var.subnet_id # Deployed into the specified subnet.
  # Associate the security group defined above.
  vpc_security_group_ids = [aws_security_group.bastion_sg.id]
  # Attach the IAM instance profile created above, granting the instance its permissions.
  iam_instance_profile = aws_iam_instance_profile.bastion_instance_profile.name

  # Security Benefit: No SSH key pair is associated. Access is solely through SSM Session Manager,
  # eliminating risks associated with SSH key management (exposure, rotation).
  # key_name = var.key_name # Explicitly commented out.

  # User data script ensures the SSM agent is installed and running.
  # While often pre-installed on modern AMIs, this provides resilience.
  user_data = <<-EOF
              #!/bin/bash
              # Ensure SSM agent is installed and running (commands might vary slightly by OS)
              sudo yum install -y https://s3.${data.aws_region.current.name}.amazonaws.com/amazon-ssm-${data.aws_region.current.name}/latest/linux_amd64/amazon-ssm-agent.rpm
              sudo systemctl enable amazon-ssm-agent
              sudo systemctl start amazon-ssm-agent
              EOF

  tags = local.common_tags

  # Ensure IAM profile is created before instance
  depends_on = [aws_iam_instance_profile.bastion_instance_profile]
}

# --- IAM Policy Document Data Source (Example for User Access) ---
# This data source generates an *example* IAM policy document JSON in the outputs.
# It is NOT applied by this module but serves as a template for administrators
# to attach to the IAM roles/users (e.g., AWS SSO permission sets) that need
# access to the bastion host.
data "aws_iam_policy_document" "ssm_start_session_policy_example" {
  # Allows starting an SSM session specifically targeting the created bastion instance.
  # Security Principle: Least Privilege - Grants access only to the intended resource.
  statement {
    sid    = "AllowSSMSessionToSpecificBastion"
    effect = "Allow"
    actions = [
      "ssm:StartSession"
    ]
    # Resource is scoped to the specific instance ID created by this module run.
    resources = [
      "arn:aws:ec2:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:instance/${aws_instance.bastion_host.id}"
    ]
    # Optional Condition: Further restrict access based on tags.
    # The external automation should apply a unique tag (e.g., SessionID) to the instance,
    # and the user's policy can require this tag for connection, ensuring they only
    # connect to the bastion provisioned for their specific request.
    # condition {
    #   test     = "StringEquals"
    #   variable = "ssm:resourceTag/SessionID"
    #   values   = [var.tags["SessionID"]] # Assumes SessionID is passed via var.tags by automation.
    # }
  }

  # Allows listing instances, which is often required by the AWS Console or CLI
  # for users to discover the instance they are allowed to connect to.
  statement {
    sid    = "AllowSSMInstanceDiscovery"
    effect = "Allow"
    actions = [
      "ssm:DescribeInstanceInformation", # Often needed for console/CLI to list instances
      "ec2:DescribeInstances"            # Needed to resolve instance IDs/tags in some tools
    ]
    resources = ["*"] # Necessary for discovery
  }

  # Optional: Enforce MFA for Session Initiation.
  # Uncomment and adapt this statement in the policy applied to user roles
  # to require MFA for starting SSM sessions.
  # statement {
  #   sid    = "DenySSMSessionIfNotMFA"
  #   effect = "Deny"
  #   actions = [
  #     "ssm:StartSession"
  #   ]
  #   resources = [
  #     "arn:aws:ec2:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:instance/${aws_instance.bastion_host.id}"
  #   ]
  #   condition {
  #     test     = "BoolIfExists"
  #     variable = "aws:MultiFactorAuthPresent"
  #     values   = ["false"]
  #   }
  # }
}
