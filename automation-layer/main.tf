# automation-layer/main.tf

terraform {
  required_version = ">= 1.8" # Updated to a more recent TF version (e.g., 1.8 or later)

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.40" # Pinning to a recent minor version series (e.g., 5.40.x)
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.1"
    }
  }

  # Configure S3 backend for the automation layer's state
  # backend "s3" {
    # Bucket name needs to be provided during init or via config file/CLI args
    # key    = "automation-layer/terraform.tfstate"
    # region = "us-east-1" # Specify your region
    # encrypt = true # Recommended
  # }
}

provider "aws" {
  region = var.aws_region
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# --- Locals & Random Suffix for Uniqueness ---
locals {
  # Combine user-provided tags with default tags for this automation layer
  automation_tags = merge(
    {
      "AutomationLayer" = var.prefix
      "Provisioner"     = "Terraform"
    },
    var.tags
  )

  # Generate a unique suffix for resources like Lambda function names if needed,
  # though using the prefix might be sufficient.
  # Using a random suffix helps avoid collisions if deploying multiple instances.
  # random_suffix = random_string.suffix.hex
}

resource "random_string" "suffix" {
  length  = 8
  special = false
  upper   = false
}

# --- S3 Bucket for Terraform State ---
resource "aws_s3_bucket" "terraform_state" {
  bucket = var.terraform_state_bucket_name # Must be globally unique
  tags   = local.automation_tags
}

# Enforce SSE and block public access for the state bucket
resource "aws_s3_bucket_server_side_encryption_configuration" "state_sse" {
  bucket = aws_s3_bucket.terraform_state.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "state_public_access" {
  bucket                  = aws_s3_bucket.terraform_state.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "state_versioning" {
  bucket = aws_s3_bucket.terraform_state.id
  versioning_configuration {
    status = "Enabled" # Recommended for state files
  }
}

# --- SSM Parameter for Authorized Users ---
resource "aws_ssm_parameter" "authorized_users" {
  name        = var.authorized_slack_user_ids_ssm_param_name
  description = "List of Slack User IDs authorized to request bastion hosts."
  type        = "StringList"
  value       = "dummy-user-id" # Placeholder - Update manually or via CI/CD after creation
  tags        = local.automation_tags

  lifecycle {
    ignore_changes = [value] # Prevent Terraform from overwriting manual updates to the list
  }
}

# --- IAM Roles and Policies ---

# Role for the Slack Handler Lambda function
resource "aws_iam_role" "slack_handler_lambda_role" {
  name = "${var.prefix}-slack-handler-role-${random_string.suffix.hex}"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17",
    Statement = [{
      Action    = "sts:AssumeRole",
      Effect    = "Allow",
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
  tags = local.automation_tags
}

# Role for the Core Orchestration Lambda function
resource "aws_iam_role" "core_orchestrator_lambda_role" {
  name = "${var.prefix}-core-orchestrator-role-${random_string.suffix.hex}"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17",
    Statement = [{
      Action    = "sts:AssumeRole",
      Effect    = "Allow",
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
  tags = local.automation_tags
}

# Role for EventBridge Scheduler to invoke the Destroy Lambda
resource "aws_iam_role" "scheduler_role" {
  name = "${var.prefix}-scheduler-role-${random_string.suffix.hex}"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17",
    Statement = [{
      Action    = "sts:AssumeRole",
      Effect    = "Allow",
      Principal = { Service = "scheduler.amazonaws.com" }
    }]
  })
  tags = local.automation_tags
}

# --- IAM Policies (Inline policies for simplicity, consider managed policies for complex scenarios) ---

# Policy for Slack Handler Lambda
resource "aws_iam_role_policy" "slack_handler_lambda_policy" {
  name = "${var.prefix}-slack-handler-policy"
  role = aws_iam_role.slack_handler_lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      # Basic Lambda execution and logging
      {
        Effect = "Allow",
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ],
        Resource = "arn:aws:logs:*:*:*" # Broad permission for logging
      },
      # Secrets Manager access for Slack secrets
      {
        Effect   = "Allow",
        Action   = "secretsmanager:GetSecretValue",
        Resource = [
          var.slack_signing_secret_arn,
          var.slack_bot_token_secret_arn
        ]
      },
      # SSM Parameter Store access for authorized users list
      {
        Effect   = "Allow",
        Action   = "ssm:GetParameter",
        Resource = "arn:aws:ssm:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:parameter${var.authorized_slack_user_ids_ssm_param_name}" # Specific parameter
      },
      # Permission to invoke the Core Orchestration Lambda
      {
        Effect   = "Allow",
        Action   = "lambda:InvokeFunction",
        Resource = aws_lambda_function.core_orchestrator_lambda.arn # Reference Core Orchestrator ARN
      }
      # Note: Does NOT need Terraform execution permissions directly
    ]
  })
}

# Policy for Core Orchestration Lambda
resource "aws_iam_role_policy" "core_orchestrator_lambda_policy" {
  name = "${var.prefix}-core-orchestrator-policy"
  role = aws_iam_role.core_orchestrator_lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      # Basic Lambda execution and logging
      {
        Effect = "Allow",
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ],
        Resource = "arn:aws:logs:*:*:*"
      },
      # S3 access for Terraform state (needs full access for isolated state files)
      {
        Effect = "Allow",
        Action = [
          "s3:ListBucket",
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject" # Needed if overwriting state or for cleanup
        ],
        Resource = [
          aws_s3_bucket.terraform_state.arn,
          "${aws_s3_bucket.terraform_state.arn}/*" # Access to objects within the bucket is crucial for state files
        ]
      },
      # EventBridge Scheduler access to create the destroy schedule
      {
        Effect = "Allow",
        Action = [
          "scheduler:CreateSchedule",
          "iam:PassRole" # Required to pass the scheduler role to EventBridge
        ],
        Resource = [
          # ARN for any schedule within the default group in the account/region
          "arn:aws:scheduler:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:schedule/default/*",
          aws_iam_role.scheduler_role.arn # Permission to pass the scheduler role
        ]
      },
      # Permissions required by Terraform to manage the specific bastion resources
      # IMPORTANT: This remains broad for the example. In a production scenario,
      # scope these permissions down tightly based *only* on what the bastion module creates/modifies.
      # Consider using permission boundaries or dynamic role assumption for better security if managing diverse modules.
      {
        Effect = "Allow",
        Action = [
          "ec2:RunInstances",
          "ec2:TerminateInstances",
          "ec2:Describe*",
          "iam:CreateRole", "iam:DeleteRole", "iam:AttachRolePolicy", "iam:DetachRolePolicy",
          "iam:CreateInstanceProfile", "iam:DeleteInstanceProfile", "iam:AddRoleToInstanceProfile", "iam:RemoveRoleFromInstanceProfile",
          "iam:PutRolePolicy", "iam:DeleteRolePolicy", "iam:PassRole",
          "s3:CreateBucket", "s3:DeleteBucket", "s3:Put*", "s3:Get*", "s3:ListBucket", "s3:DeleteObject",
          "logs:CreateLogGroup", "logs:DeleteLogGroup", "logs:PutRetentionPolicy", "logs:DescribeLogGroups"
          # Add any other permissions your bastion module requires
        ],
        Resource = "*" # WARNING: Broad permissions - scope down if possible
      }
    ]
  })
}

# Policy for Destroy Lambda (Remains largely the same, needs TF destroy permissions)
resource "aws_iam_role_policy" "destroy_lambda_policy" {
  name = "${var.prefix}-destroy-lambda-policy"
  role = aws_iam_role.destroy_lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      # Basic Lambda execution and logging
      {
        Effect = "Allow",
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ],
        Resource = "arn:aws:logs:*:*:*"
      },
      # S3 access for Terraform state
      {
        Effect = "Allow",
        Action = [
          "s3:ListBucket",
          "s3:GetObject",
          "s3:PutObject", # Potentially needed if destroy modifies state
          "s3:DeleteObject"
        ],
        Resource = [
          aws_s3_bucket.terraform_state.arn,
          "${aws_s3_bucket.terraform_state.arn}/*" # Needs access to state objects
        ]
      },
      # Permissions required by Terraform to destroy the specific bastion resources
      # IMPORTANT: Scope these down tightly. Should mirror destroy-related permissions from the core orchestrator policy.
      {
        Effect = "Allow",
        Action = [
          "ec2:TerminateInstances",
          "ec2:Describe*", # Often needed by TF providers during destroy
          "iam:DeleteRole", "iam:DetachRolePolicy",
          "iam:DeleteInstanceProfile", "iam:RemoveRoleFromInstanceProfile",
          "iam:DeleteRolePolicy",
          "s3:DeleteBucket", "s3:DeleteObject", "s3:ListBucket", # If module creates bucket
          "logs:DeleteLogGroup", "logs:DescribeLogGroups" # If module creates log group
          # Add any other destroy permissions your bastion module requires
        ],
        Resource = "*" # WARNING: Broad permissions - scope down if possible
      }
    ]
  })
}

# Policy for EventBridge Scheduler Role to invoke Destroy Lambda
resource "aws_iam_role_policy" "scheduler_invoke_policy" {
  name = "${var.prefix}-scheduler-invoke-policy"
  role = aws_iam_role.scheduler_role.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect   = "Allow",
      Action   = "lambda:InvokeFunction",
      Resource = aws_lambda_function.destroy_lambda.arn # Target the Destroy Lambda
    }]
  })
}


# --- Lambda Functions (Placeholders - Assuming Container Images) ---
# Define the Lambda functions. The actual container images need to be built and pushed separately.

# Slack Handler Lambda
resource "aws_lambda_function" "slack_handler_lambda" {
  # TODO: Replace with actual ECR image URI for the Slack Handler
  image_uri    = "123456789012.dkr.ecr.${data.aws_region.current.name}.amazonaws.com/${var.prefix}-slack-handler:latest"
  function_name = "${var.prefix}-slack-handler-${random_string.suffix.hex}"
  role          = aws_iam_role.slack_handler_lambda_role.arn
  package_type  = "Image"
  timeout       = 30 # Should be relatively quick: verify, authz, invoke orchestrator
  memory_size   = 256 # Adjust as needed

  # Conditionally configure VPC access
  vpc_config {
    subnet_ids         = var.lambda_subnet_ids != null ? var.lambda_subnet_ids : null
    security_group_ids = var.lambda_security_group_ids != null ? var.lambda_security_group_ids : null
  }

  tags = local.automation_tags

  environment {
    variables = {
      CORE_ORCHESTRATOR_FUNC_NAME = aws_lambda_function.core_orchestrator_lambda.function_name
      AUTH_USER_SSM_PARAM         = var.authorized_slack_user_ids_ssm_param_name
      SLACK_SIGNING_SECRET_ARN    = var.slack_signing_secret_arn
      SLACK_BOT_TOKEN_SECRET_ARN  = var.slack_bot_token_secret_arn
    }
  }
}

# Core Orchestration Lambda
resource "aws_lambda_function" "core_orchestrator_lambda" {
  # TODO: Replace with actual ECR image URI for the Core Orchestrator (needs Python, TF, bastion module code)
  image_uri    = "123456789012.dkr.ecr.${data.aws_region.current.name}.amazonaws.com/${var.prefix}-core-orchestrator:latest"
  function_name = "${var.prefix}-core-orchestrator-${random_string.suffix.hex}"
  role          = aws_iam_role.core_orchestrator_lambda_role.arn
  package_type  = "Image"
  timeout       = 900 # Max timeout for Terraform apply
  memory_size   = 512 # Adjust as needed

  # Conditionally configure VPC access
  vpc_config {
    subnet_ids         = var.lambda_subnet_ids != null ? var.lambda_subnet_ids : null
    security_group_ids = var.lambda_security_group_ids != null ? var.lambda_security_group_ids : null
  }

  tags = local.automation_tags

  # Add environment variables if needed (e.g., TF state bucket, SSM param name)
  environment {
    variables = {
      TF_STATE_BUCKET        = aws_s3_bucket.terraform_state.id
      DEFAULT_LIFETIME_MIN   = var.bastion_session_default_lifetime_minutes
      DESTROY_LAMBDA_ARN     = aws_lambda_function.destroy_lambda.arn # Pass ARN for scheduling
      SCHEDULER_ROLE_ARN     = aws_iam_role.scheduler_role.arn      # Pass Role ARN for scheduling
      BASTION_MODULE_SOURCE  = var.bastion_module_source # Location of the bastion module code
      BASTION_VPC_ID         = var.bastion_vpc_id
      BASTION_SUBNET_ID      = var.bastion_subnet_id
      BASTION_INSTANCE_TYPE  = var.bastion_instance_type
      # Pass other necessary bastion vars required by the module itself
      BASTION_VPC_ID         = var.bastion_vpc_id
      BASTION_SUBNET_ID      = var.bastion_subnet_id
      BASTION_INSTANCE_TYPE  = var.bastion_instance_type
    }
  }
}

# Destroy Handler Lambda
resource "aws_lambda_function" "destroy_lambda" {
  # TODO: Replace with actual ECR image URI for the Destroy Handler (needs Python, TF)
  image_uri    = "123456789012.dkr.ecr.${data.aws_region.current.name}.amazonaws.com/${var.prefix}-destroy:latest"
  function_name = "${var.prefix}-destroy-${random_string.suffix.hex}"
  role          = aws_iam_role.destroy_lambda_role.arn
  package_type  = "Image"
  timeout       = 900 # Max timeout for Terraform destroy
  memory_size   = 512 # Adjust as needed

  # Conditionally configure VPC access
  vpc_config {
    subnet_ids         = var.lambda_subnet_ids != null ? var.lambda_subnet_ids : null
    security_group_ids = var.lambda_security_group_ids != null ? var.lambda_security_group_ids : null
  }

  tags = local.automation_tags

  environment {
    variables = {
      TF_STATE_BUCKET = aws_s3_bucket.terraform_state.id
    }
  }
}

# --- API Gateway (HTTP API) ---
resource "aws_apigatewayv2_api" "slack_api" {
  name          = "${var.prefix}-http-api"
  protocol_type = "HTTP"
  description   = "API Gateway for Slack Bastion Requests"
  tags          = local.automation_tags
}

resource "aws_apigatewayv2_stage" "default_stage" {
  api_id      = aws_apigatewayv2_api.slack_api.id
  name        = "$default" # Default stage
  auto_deploy = true
  tags        = local.automation_tags
}

resource "aws_apigatewayv2_integration" "lambda_integration" {
  api_id           = aws_apigatewayv2_api.slack_api.id
  integration_type = "AWS_PROXY" # Sends the entire request to Lambda
  integration_uri    = aws_lambda_function.slack_handler_lambda.invoke_arn # Target the Slack Handler
  payload_format_version = "2.0" # Use the newer payload format
}

resource "aws_apigatewayv2_route" "slack_route" {
  api_id    = aws_apigatewayv2_api.slack_api.id
  route_key = "POST /slack/events" # The path Slack will POST to
  target    = "integrations/${aws_apigatewayv2_integration.lambda_integration.id}"
}

# --- Lambda Permissions ---

# Allow API Gateway to invoke the Slack Handler Lambda
resource "aws_lambda_permission" "api_gw_invoke_slack_handler" {
  statement_id  = "AllowAPIGatewayInvokeSlackHandler"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.slack_handler_lambda.function_name
  principal     = "apigateway.amazonaws.com"

  # Restrict permission to the specific API Gateway API and route
  source_arn = "${aws_apigatewayv2_api.slack_api.execution_arn}/*/${aws_apigatewayv2_route.slack_route.route_key}"
}

# --- Outputs ---
output "api_gateway_endpoint" {
  description = "The HTTPS endpoint URL for the API Gateway. Configure this in your Slack App's Slash Command."
  value       = "${aws_apigatewayv2_api.slack_api.api_endpoint}${aws_apigatewayv2_route.slack_route.route_key}" # Full URL for Slack config
}

output "terraform_state_bucket_name" {
  description = "Name of the S3 bucket created for Terraform state."
  value       = aws_s3_bucket.terraform_state.id
}

output "authorized_users_ssm_parameter_name" {
  description = "Name of the SSM Parameter storing authorized Slack User IDs. Update this parameter with actual IDs."
  value       = aws_ssm_parameter.authorized_users.name
}

output "slack_handler_lambda_role_arn" {
  description = "ARN of the IAM Role for the Slack Handler Lambda."
  value       = aws_iam_role.slack_handler_lambda_role.arn
}

output "core_orchestrator_lambda_role_arn" {
  description = "ARN of the IAM Role for the Core Orchestration Lambda."
  value       = aws_iam_role.core_orchestrator_lambda_role.arn
}

output "destroy_lambda_role_arn" {
  description = "ARN of the IAM Role for the Destroy Lambda."
  value       = aws_iam_role.destroy_lambda_role.arn
}

output "scheduler_role_arn" {
  description = "ARN of the IAM Role for the EventBridge Scheduler."
  value       = aws_iam_role.scheduler_role.arn
}
