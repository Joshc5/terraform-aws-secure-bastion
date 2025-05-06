# Terraform AWS Secure Bastion On-Demand Module

## Overview

This Terraform module provisions the necessary AWS infrastructure for a **secure, ephemeral bastion host** accessible *only* via **AWS Systems Manager (SSM) Session Manager**. This approach prioritizes security by design and is intended for integration with an external automation layer (e.g., Lambda triggered by API Gateway or Slack) that manages the lifecycle (on-demand provisioning and automated destruction).

**Core Security Principles:**

*   **Reduced Attack Surface:** By leveraging SSM Session Manager, this module **eliminates the need for open inbound ports (like SSH port 22)** on the bastion's security group. Access is initiated via outbound connections from the SSM agent, drastically minimizing exposure to network scanning and brute-force attacks.
*   **Ephemeral Infrastructure:** The bastion host is designed to be short-lived, created only when needed and automatically destroyed after a predefined period by the external automation. This minimizes the window of opportunity for compromise.
*   **IAM-Based Access Control:** Authentication and authorization rely entirely on AWS IAM roles and policies, integrating seamlessly with **AWS IAM Identity Center** (formerly AWS SSO). This allows for centralized management, fine-grained permissions, and standard AWS auditing.
*   **Auditable Sessions:** Session activity is logged to **CloudWatch Logs** and/or an **S3 bucket**, providing a clear audit trail of who accessed the bastion, when, and what commands were run (if configured in SSM preferences).

> **💡 Important Note:** This module focuses *solely* on creating the secure bastion infrastructure components (EC2, IAM Roles, Security Groups, Logging). To achieve the on-demand, ephemeral lifecycle, it needs to be integrated with an automation system that handles triggering, user authorization, and timed destruction. An optional Slack-based automation layer is included in the [`automation-layer/`](./automation-layer/) directory as one example implementation.

🛠️ My long term goal is to expand upon this automation layer feature into its own project where it becomes an entire ChatOps (Slack/Teams/Webex/etc.) orchestration framework for seamless (and secure) infrastructure deployment, SecOps tasks, Incident Response, and more.

---

## ✨ Features & Security Benefits

*   Provisions an **EC2 instance** to serve as the bastion host.
*   Configures an **IAM Role** and **Instance Profile** adhering to the principle of least privilege.
    *   *Security:* Grants only the necessary permissions (`AmazonSSMManagedInstanceCore` plus specific permissions for logging to S3/CloudWatch).
*   Creates a **Security Group** with **no inbound rules**.
    *   *Security:* Access relies on SSM Session Manager's outbound connection model, significantly reducing the network attack surface compared to traditional SSH bastions. Allows only essential outbound HTTPS for SSM agent communication and optional OS patching.
*   **(Optional)** Creates a secure **S3 bucket** for storing SSM session logs:
    *   *Security:* Enforces Server-Side Encryption (SSE-S3) to protect logs at rest.
    *   *Security:* Enables Public Access Block to prevent accidental data exposure.
    *   Lifecycle policy for log retention
*   **(Optional)** Creates a **CloudWatch Log Group** for storing SSM session logs with configurable retention for alternative log aggregation and analysis.
*   Outputs an example **IAM policy document** (JSON) demonstrating how to grant users `ssm:StartSession` access, scoped to the specific bastion instance.
    *   *Security:* Facilitates implementing least-privilege access for users connecting via SSM.

---

## 📋 Prerequisites

*   **Terraform** v1.8+ (Recommended, aligns with automation layer)
*   **AWS Provider** ~> 5.40 (or the version specified in `main.tf`)
*   Configured AWS credentials (consider using OIDC, IAM Roles, etc.)
*   An existing **VPC** and **Subnet ID** where the bastion will be deployed.
*   **(Highly Recommended for Maximum Security)** **VPC Endpoints** for SSM (`ssm`, `ssmmessages`, `ec2messages`) within your VPC.
    *   *Security:* Allows the bastion to reside in a **private subnet** with no direct internet access (no Internet Gateway or NAT Gateway needed for SSM), further isolating it. The SSM agent communicates securely via the private endpoints.
*   **(If not using the included `automation-layer/`)** An **external automation system** (e.g., custom Lambda, Step Functions, CI/CD pipeline) capable of:
    *   *Security:* Securely authenticating and authorizing user requests before triggering this module.
    *   Executing `terraform apply` for this module with appropriate variables.
    *   Scheduling and executing `terraform destroy` (potentially targeted) after a defined session lifetime.

---

## 🤖 Optional Slack Automation Layer

This repository also includes an optional, serverless automation layer in the [`automation-layer/`](./automation-layer/) directory. This layer provides:

*   A Slack Slash Command interface (e.g., `/request-bastion`) for users to request bastion hosts.
*   Secure handling of Slack requests (signature verification).
*   Authorization checks based on Slack User IDs stored in SSM Parameter Store.
*   Orchestration of `terraform apply` using this bastion module.
*   Automatic scheduling of `terraform destroy` via EventBridge Scheduler.
*   Notifications back to the requesting user in Slack.

This provides a complete end-to-end solution for on-demand bastion access via Slack. See the [Automation Layer README](./automation-layer/README.md) for detailed setup and usage instructions for that component.

---

## 🚀 Module Usage Example (Manual or Custom Automation)

This example shows how you might call the module from within the Terraform configuration used by your automation trigger (e.g., a Lambda function's deployment package).

```terraform
# main.tf (in your automation project)

module "secure_bastion" {
  # Use a relative path, Git URL, or Terraform Registry source
  source = "./modules/aws-secure-bastion-on-demand" 

  # --- Required Inputs ---
  vpc_id                     = "vpc-0123456789abcdef0"
  subnet_id                  = "subnet-0123456789abcdef0" # Ideally a private subnet with VPC endpoints
  allowed_ssm_principal_arns = [
    # List of IAM Role/User ARNs allowed to connect (e.g., from AWS SSO)
    "arn:aws:iam::111122223333:role/aws-reserved/sso.amazonaws.com/eu-west-1/AWSReservedSSO_YourReadOnlyRole_...",
    "arn:aws:iam::111122223333:role/aws-reserved/sso.amazonaws.com/eu-west-1/AWSReservedSSO_YourAdminRole_..."
  ]

  # --- Optional Inputs ---
  instance_type = "t3.small" # Default: "t3.micro"
  
  # Example: Use an existing S3 bucket and CloudWatch Log Group
  # create_s3_bucket                  = false 
  # session_log_s3_bucket_name        = "my-central-ssm-logs-bucket"
  # create_cloudwatch_log_group       = false
  # session_log_cloudwatch_group_name = "/aws/ssm/central-session-logs"
  # log_retention_days                = 180 # Default: 90
  # s3_log_retention_days             = 730 # Default: 365

  # --- Tags ---
  tags = {
    # Tags provided by the automation layer are crucial for tracking and cleanup
    RequestingUser = "jane.doe@example.com" 
    SessionID      = "session-xyz-789"      
    RequestTime    = "2025-04-26T14:50:00Z"
    # Additional organizational tags
    Environment    = "production"
    CostCenter     = "security-operations"
    Project        = "SecureAccess"
  }
}

# --- Example External Automation Workflow (Conceptual) ---
# If *not* using the provided automation-layer, you would build something similar:
# 1. Trigger: Receive request (API call, custom web UI, etc.).
# 2. AuthN/AuthZ: Verify user identity and permissions.
# 3. Prepare Context: Generate a unique SessionID, get user identifier, determine desired lifetime.
# 4. Execute Terraform: 
#    - `terraform init`
#    - `terraform apply -auto-approve -var 'tags={SessionID="...", RequestingUser="..."}' ...`
# 5. Extract Output: Get `bastion_instance_id` from Terraform state/output.
# 6. Schedule Cleanup: Use EventBridge Scheduler (or similar) to trigger a cleanup Lambda after the session lifetime.
# 7. Cleanup Lambda: 
#    - `terraform init`
#    - `terraform destroy -auto-approve -target=module.secure_bastion.aws_instance.bastion_host` (using the specific instance ID ensures only that session's bastion is removed). Consider robust state management.
# 8. Notify User: Send connection details back to the user:
#    `aws ssm start-session --target <bastion_instance_id> --region <your-region>`
```

---

## 🔐 Granting User Access (IAM Policy)

Access to the bastion via SSM Session Manager is controlled entirely by IAM. Users (or the roles they assume via AWS SSO) require specific IAM permissions. This module outputs an example policy JSON (`ssm_start_session_policy_example_json`) which serves as a template.

**Security Best Practices for User Policies:**

1.  **Least Privilege (`ssm:StartSession`):** Grant `ssm:StartSession` permission **only** for the specific bastion instance being created. Use the instance ARN (`arn:aws:ec2:REGION:ACCOUNT_ID:instance/INSTANCE_ID`) as the `Resource`. You can retrieve the `bastion_instance_id` from the module's output in your automation.
    ```json
    "Resource": "arn:aws:ec2:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:instance/${module.secure_bastion.bastion_instance_id}"
    ```
2.  **Tag-Based Conditions (Optional but Recommended):** For enhanced security, especially with multiple concurrent bastions, add an IAM condition checking for a unique tag (e.g., `SessionID` or `RequestingUserARN`) applied to the instance by your automation layer. This ensures users can only connect to the bastion specifically provisioned for their request.
    ```json
    "Condition": {
        "StringEquals": {
            "ssm:resourceTag/SessionID": "${user_session_id_variable}" 
        }
    }
    ```
3.  **Discovery Permissions:** Grant `ssm:DescribeInstanceInformation` and `ec2:DescribeInstances` with `Resource: "*"` if users need to list instances via the AWS Console or CLI to find the bastion. These permissions do not grant connection ability.
4.  **MFA Enforcement:** Require users to authenticate with MFA before they can start a session. Add an IAM condition to the policy attached to the user's role. Use *either* an `Allow` with a check for MFA *or* a `Deny` if MFA is absent:

    *   **Option A (Allow only if MFA present):** Add to the `Allow` statement for `ssm:StartSession`:
        ```json
        "Condition": {
            "Bool": { "aws:MultiFactorAuthPresent": "true" }
        }
        ```
    *   **Option B (Deny if MFA not present):** Add a separate `Deny` statement:
        ```json
        {
            "Sid": "DenySSMSessionIfNotMFA",
            "Effect": "Deny",
            "Action": "ssm:StartSession",
            "Resource": "arn:aws:ec2:REGION:ACCOUNT_ID:instance/*", // Scope appropriately
            "Condition": {
                "BoolIfExists": { "aws:MultiFactorAuthPresent": "false" }
            }
        }
        ```

---

## 🛡️ Security Considerations Summary

This module is designed with security as a primary focus:

1.  **No Open Inbound Ports:** Relies on SSM Session Manager, eliminating the need to expose SSH or other ports to the internet, drastically reducing the attack surface.
2.  **IAM-Centric Access:** Leverages robust AWS IAM for authentication and authorization, allowing fine-grained control and integration with identity providers like AWS IAM Identity Center (SSO).
3.  **Ephemeral Nature:** The intended workflow involves creating bastions on-demand and destroying them automatically after use, minimizing the time any potential vulnerability or compromise could be exploited. (Requires external automation).
4.  **Auditing:** SSM Session Manager provides logging capabilities (to CloudWatch Logs and/or S3) for session activity, enhancing visibility and accountability. CloudTrail logs API calls for session start/stop.
5.  **No SSH Key Management:** By exclusively using SSM, the risks associated with managing, distributing, and rotating SSH keys are eliminated.
6.  **Least Privilege (IAM Roles):** The IAM role for the EC2 instance and the example user policy emphasize granting only the minimum necessary permissions.
7.  **Secure Logging Defaults:** When creating logging resources (S3 bucket), encryption at rest and public access blocks are enabled by default.
8.  **Private Subnet Deployment:** Deployment in private subnets using VPC endpoints for maximum network isolation.

---

## ⚙️ Inputs

| Name                                | Description                                                                                                     | Type           | Default                            | Required |
| :---------------------------------- | :-------------------------------------------------------------------------------------------------------------- | :------------- | :--------------------------------- | :------: |
| `vpc_id`                            | ID of the VPC where the bastion host will reside.                                                               | `string`       | -                                  |   ✅    |
| `subnet_id`                         | ID of the Subnet for the bastion host. Should ideally be a private subnet if using VPC endpoints for SSM.       | `string`       | -                                  |   ✅    |
| `allowed_ssm_principal_arns`        | List of IAM Role/User ARNs allowed to start SSM sessions on this bastion host.                                  | `list(string)` | -                                  |   ✅    |
| `instance_type`                     | EC2 instance type for the bastion host.                                                                         | `string`       | `"t3.micro"`                       |    ❌    |
| `ami_id`                            | Specific AMI ID to use. If `null`, the latest Amazon Linux 2023 AMI for the region will be used.                  | `string`       | `null`                             |    ❌    |
| `bastion_name_prefix`               | Prefix for naming resources created by this module (e.g., EC2 instance, IAM role, SG).                            | `string`       | `"aws-secure-bastion-on-demand"` |    ❌    |
| `session_log_s3_bucket_name`        | Name of an *existing* S3 bucket for storing SSM session logs. If `null`, a new bucket will be created.            | `string`       | `null`                             |    ❌    |
| `session_log_cloudwatch_group_name` | Name of an *existing* CloudWatch Log Group for storing SSM session logs. If `null`, a new log group will be created. | `string`       | `null`                             |    ❌    |
| `log_retention_days`                | Retention period in days for CloudWatch logs (if created by module).                                            | `number`       | `90`                               |    ❌    |
| `s3_log_retention_days`             | Retention period in days for S3 logs via lifecycle rule (if bucket created by module).                          | `number`       | `365`                              |    ❌    |
| `tags`                              | A map of additional tags to apply to all taggable resources. Crucial for tracking/cleanup by automation.        | `map(string)`  | `{}`                               |    ❌    |
| `create_s3_bucket`                  | Controls creation of the S3 bucket. Automatically `false` if `session_log_s3_bucket_name` is provided.           | `bool`         | `true`                             |    ❌    |
| `create_cloudwatch_log_group`       | Controls creation of the CloudWatch Log Group. Automatically `false` if `session_log_cloudwatch_group_name` is provided. | `bool`         | `true`                             |    ❌    |

---

## 📤 Outputs

| Name                                     | Description                                                                                                                                                              |
| :--------------------------------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `bastion_instance_id`                    | The ID of the EC2 instance created. **Needed** for the `aws ssm start-session` command and potentially for targeted `terraform destroy`.                                 |
| `bastion_iam_role_arn`                   | The ARN of the IAM role attached to the bastion host instance.                                                                                                           |
| `session_logs_s3_bucket_id`              | The ID (name) of the S3 bucket used for session logs. Only set if the bucket was created by this module (`create_s3_bucket` was `true`).                                  |
| `session_logs_cloudwatch_log_group_name` | The name of the CloudWatch Log Group used for session logs. Only set if the log group was created by this module (`create_cloudwatch_log_group` was `true`).              |
| `ssm_start_session_policy_example_json`  | An example IAM policy JSON document (as a string) that can be adapted and attached to user/role principals to grant `ssm:StartSession` permission on this specific bastion. |
