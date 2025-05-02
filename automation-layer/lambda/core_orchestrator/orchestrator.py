# automation-layer/lambda/core_orchestrator/orchestrator.py

import json
import os
import logging
import subprocess
import tempfile
import shutil
import uuid
import boto3
from datetime import datetime, timedelta
# import requests # No longer sending response directly from here

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Environment variables (passed from Terraform)
TF_STATE_BUCKET = os.environ['TF_STATE_BUCKET']
DEFAULT_LIFETIME_MIN = int(os.environ.get('DEFAULT_LIFETIME_MIN', 240))
DESTROY_LAMBDA_ARN = os.environ['DESTROY_LAMBDA_ARN']
SCHEDULER_ROLE_ARN = os.environ['SCHEDULER_ROLE_ARN']
BASTION_MODULE_SOURCE = os.environ['BASTION_MODULE_SOURCE']
# Bastion specific vars (passed for convenience, could be part of payload)
BASTION_VPC_ID = os.environ.get('BASTION_VPC_ID')
BASTION_SUBNET_ID = os.environ.get('BASTION_SUBNET_ID')
BASTION_INSTANCE_TYPE = os.environ.get('BASTION_INSTANCE_TYPE', 't3.micro')

# Initialize AWS clients
scheduler = boto3.client('scheduler')
s3 = boto3.client('s3') # Needed? Maybe just for cleanup on failure

# --- Helper Functions ---

def run_terraform_command(command_args, working_dir, session_id, state_key):
    """Runs a Terraform command using subprocess."""
    env = os.environ.copy()
    # Configure S3 backend dynamically
    backend_config = f"""
terraform {{
  backend "s3" {{
    bucket = "{TF_STATE_BUCKET}"
    key    = "{state_key}"
    region = "{os.environ['AWS_REGION']}" # Assumes AWS_REGION is set in Lambda env
    encrypt = true
  }}
}}
"""
    backend_file_path = os.path.join(working_dir, "backend.tf.override")
    with open(backend_file_path, "w") as f:
        f.write(backend_config)
    logger.info(f"Created backend override file at {backend_file_path}")

    # Base command includes init
    base_command = ["terraform", f"-chdir={working_dir}"]
    init_command = base_command + ["init", "-no-color", "-input=false"]
    full_command = base_command + command_args

    try:
        logger.info(f"Running Terraform init: {' '.join(init_command)}")
        init_process = subprocess.run(init_command, capture_output=True, text=True, check=True, env=env)
        logger.info("Terraform init stdout:\n" + init_process.stdout)
        logger.info("Terraform init stderr:\n" + init_process.stderr)

        logger.info(f"Running Terraform command: {' '.join(full_command)}")
        process = subprocess.run(full_command, capture_output=True, text=True, check=True, env=env)
        logger.info("Terraform command stdout:\n" + process.stdout)
        logger.info("Terraform command stderr:\n" + process.stderr)
        return process.stdout, process.stderr
    except subprocess.CalledProcessError as e:
        logger.error(f"Terraform command failed: {e}")
        logger.error("Terraform stdout:\n" + e.stdout)
        logger.error("Terraform stderr:\n" + e.stderr)
        raise # Re-raise the exception to be caught by the handler
    finally:
        # Clean up backend override file
        if os.path.exists(backend_file_path):
            os.remove(backend_file_path)

def parse_tf_output(stdout):
    """Parses Terraform output JSON from stdout."""
    try:
        # Find the JSON output part
        json_start = stdout.find('{')
        json_end = stdout.rfind('}') + 1
        if json_start != -1 and json_end != -1:
            output_json = json.loads(stdout[json_start:json_end])
            # Extract specific values (adjust keys based on actual module outputs)
            instance_id = output_json.get("bastion_instance_id", {}).get("value")
            return {"bastion_instance_id": instance_id}
        else:
            logger.warning("Could not find JSON output in Terraform stdout.")
            return {}
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse Terraform output JSON: {e}")
        return {}
    except Exception as e:
        logger.error(f"Error parsing Terraform output: {e}")
        return {}


def schedule_destruction(session_id, lifetime_minutes):
    """Creates an EventBridge schedule to trigger the destroy lambda."""
    schedule_name = f"bastion-destroy-{session_id}"
    schedule_time = datetime.utcnow() + timedelta(minutes=lifetime_minutes)
    # Format for EventBridge: yyyy-mm-ddThh:mm:ss
    schedule_expression = f"at({schedule_time.strftime('%Y-%m-%dT%H:%M:%S')})"

    logger.info(f"Creating schedule '{schedule_name}' for {schedule_expression}")

    try:
        scheduler.create_schedule(
            Name=schedule_name,
            ActionAfterCompletion='DELETE', # Delete schedule after it runs once
            FlexibleTimeWindow={'Mode': 'OFF'},
            ScheduleExpression=schedule_expression,
            Target={
                'Arn': DESTROY_LAMBDA_ARN,
                'RoleArn': SCHEDULER_ROLE_ARN,
                'Input': json.dumps({'SessionID': session_id}) # Pass SessionID to destroy lambda
            },
            State='ENABLED'
        )
        logger.info(f"Successfully created EventBridge schedule: {schedule_name}")
        return True
    except Exception as e:
        logger.error(f"Error creating EventBridge schedule: {e}")
        return False

# Note: This function is now primarily for logging the *intent* to send a message.
# The actual sending should be handled by the Slack Handler based on the
# return value of the main orchestrator handler or via separate error reporting.
def log_slack_response_intent(response_url, message_payload, is_error=False):
    """Logs the message intended for Slack, using generic messages for errors."""
    if is_error:
        generic_error_text = ":x: An internal error occurred during bastion processing. Please contact the administrator."
        logger.error(f"Intended Slack error response (URL: {response_url}): {generic_error_text}. Original details: {message_payload.get('text', 'No text provided')}")
    else:
        logger.info(f"Intended Slack response (URL: {response_url}): {message_payload.get('text', 'No text provided')}")
    # Actual sending via requests.post is removed from this function.


# --- Main Handler ---

def handler(event, context):
    """
    Handles invocation from Slack Handler (or other triggers).
    Executes Terraform apply, schedules destruction, and reports status.
    """
    logger.info(f"Received event: {json.dumps(event)}")

    # --- Input Validation ---
    try:
        requesting_user_id = event['requesting_user_id']
        requesting_user_name = event['requesting_user_name']
        response_url = event['response_url']
        bastion_params = event.get('bastion_params', {})

        # Validate required bastion params (passed via env or payload)
        vpc_id = bastion_params.get('vpc_id', BASTION_VPC_ID)
        subnet_id = bastion_params.get('subnet_id', BASTION_SUBNET_ID)
        if not vpc_id or not subnet_id:
            raise ValueError("Missing required bastion parameters: vpc_id or subnet_id")

        # Validate optional params
        lifetime_minutes = int(bastion_params.get('lifetime_minutes', DEFAULT_LIFETIME_MIN))
        if lifetime_minutes <= 0 or lifetime_minutes > 1440: # Example bounds (1 day max)
             raise ValueError(f"Invalid lifetime_minutes specified (must be > 0 and <= {DEFAULT_LIFETIME_MIN}).") # Use configured default as max for example
        instance_type = bastion_params.get('instance_type', BASTION_INSTANCE_TYPE)
        # Example validation using allowed list (needs allowed_instance_types defined or passed)
        # allowed_instance_types = ['t3.micro', 't3.small'] # Define this globally or pass via env
        # if instance_type not in allowed_instance_types:
        #     raise ValueError(f"Invalid instance_type '{instance_type}'. Allowed: {allowed_instance_types}")

    except (KeyError, ValueError, TypeError) as e:
        error_detail = f"Invalid input parameters received by orchestrator: {e}"
        logger.error(error_detail)
        # Log intent to send generic error message back via the response_url
        # The Slack Handler is responsible for actually sending the message based on this lambda's failure.
        # However, logging the intent here helps trace the flow.
        if event.get('response_url'):
            log_slack_response_intent(event['response_url'], {'text': error_detail}, is_error=True) # Log intent with detail
        # Since this Lambda is invoked asynchronously ('Event'), returning an error
        # doesn't directly go back to the Slack Handler in the standard request/response flow.
        # We rely on logging and potentially a Dead Letter Queue (DLQ) or other monitoring.
        # For synchronous testing or if the caller handles exceptions, raising is an option:
        # raise Exception(error_detail)
        # Returning a structured error is useful for logging and potential DLQ analysis.
        return {'status': 'error', 'message': "Invalid input parameters"} # Generic message in return

    # --- Terraform Execution ---
    session_id = str(uuid.uuid4()) # Unique ID for this bastion instance/session
    tf_dir = None
    instance_id = None
    tf_success = False

    try:
        # Create a temporary directory to run Terraform
        tf_dir = tempfile.mkdtemp()
        logger.info(f"Created temporary Terraform directory: {tf_dir}")

        # Copy or link the bastion module code into the temp directory
        # Assumes the module code is bundled with the Lambda container
        module_path_in_container = "/var/task/bastion_module" # Adjust if needed based on Dockerfile
        target_module_dir = os.path.join(tf_dir, "bastion_module")
        # If BASTION_MODULE_SOURCE points elsewhere (e.g., Git), logic to fetch it would go here.
        # For now, assume it's bundled.
        if os.path.exists(module_path_in_container):
             shutil.copytree(module_path_in_container, target_module_dir)
             logger.info(f"Copied bastion module from {module_path_in_container} to {target_module_dir}")
        else:
             raise FileNotFoundError(f"Bastion module code not found at {module_path_in_container}")


        # Create a root module file in the temp dir to call the bastion module
        main_tf_content = f"""
module "secure_bastion" {{
  source = "./bastion_module" # Use the copied module

  # Required inputs
  vpc_id      = "{vpc_id}"
  subnet_id   = "{subnet_id}"
  # allowed_ssm_principal_arns = [] # TODO: Decide how to handle this - pass from Slack? Fixed list?

  # Optional inputs
  instance_type = "{instance_type}"
  # bastion_log_s3_bucket_name = ... # Pass if provided
  # bastion_log_cloudwatch_group_name = ... # Pass if provided

  tags = {{
    RequestingUser = "{requesting_user_id}"
    RequestingUserName = "{requesting_user_name}"
    SessionID      = "{session_id}"
    Provisioner    = "SlackAutomationLambda"
  }}
}}

output "bastion_instance_id" {{
  value = module.secure_bastion.bastion_instance_id
}}
# Add other outputs if needed by the automation
"""
        with open(os.path.join(tf_dir, "main.tf"), "w") as f:
            f.write(main_tf_content)
        logger.info("Created main.tf in temporary directory.")

        # Define Terraform command arguments
        tf_state_key = f"bastion-state/{session_id}.tfstate"
        apply_args = ["apply", "-auto-approve", "-no-color", "-input=false"]
        output_args = ["output", "-json"]

        # Run Terraform Apply
        apply_stdout, apply_stderr = run_terraform_command(apply_args, tf_dir, session_id, tf_state_key)

        # Run Terraform Output to get instance ID
        output_stdout, output_stderr = run_terraform_command(output_args, tf_dir, session_id, tf_state_key)
        tf_outputs = parse_tf_output(output_stdout)
        instance_id = tf_outputs.get("bastion_instance_id")

        if not instance_id:
            raise Exception("Failed to retrieve bastion_instance_id from Terraform output.")

        logger.info(f"Terraform apply successful. Bastion Instance ID: {instance_id}")
        tf_success = True

    except Exception as e:
        error_detail = f"Error during Terraform execution for SessionID {session_id}: {e}"
        logger.error(error_detail)
        # Log intent to send generic error message
        log_slack_response_intent(response_url, {'text': error_detail}, is_error=True)
        # Attempt cleanup of state file if apply failed partially? This is complex.
        # A common pattern is to leave the state file for manual inspection on failure.
        # Consider adding logic to delete the S3 state object if apply *definitely* failed early.
        # raise Exception(error_detail) # Option: Fail the Lambda execution
        return {'status': 'error', 'message': "Terraform execution failed"} # Generic message in return
    finally:
        # Clean up the temporary directory regardless of success/failure
        if tf_dir and os.path.exists(tf_dir):
            logger.info(f"Cleaning up temporary directory: {tf_dir}")
            shutil.rmtree(tf_dir)

    # --- Schedule Destruction ---
    schedule_success = False
    if tf_success and instance_id:
        try:
            schedule_success = schedule_destruction(session_id, lifetime_minutes)
            if not schedule_success:
                 # This is problematic - bastion exists but won't be auto-destroyed.
                 # Requires manual intervention or a more robust retry/cleanup mechanism (e.g., DLQ on scheduler failure).
                 error_detail = f"Bastion created ({instance_id}) but FAILED to schedule automatic destruction. Manual cleanup required! SessionID: {session_id}"
                 logger.error(error_detail)
                 # Log intent to send warning message (Slack handler needs to interpret the return status)
                 log_slack_response_intent(response_url, {'text': f":warning: {error_detail}"}) # Log intent
                 # Update status to indicate partial success
                 schedule_success = False # Ensure this flag is correctly set
            else:
                 logger.info(f"Successfully scheduled destruction for SessionID: {session_id}")

        except Exception as e:
            error_detail = f"Bastion created ({instance_id}) but encountered an error scheduling destruction: {e}. Manual cleanup required! SessionID: {session_id}"
            logger.error(error_detail)
            # Log intent to send warning message
            log_slack_response_intent(response_url, {'text': f":warning: {error_detail}"}) # Log intent
            schedule_success = False # Ensure this flag is correctly set

    # --- Prepare and Log Final Slack Notification Intent / Return Status ---
    if tf_success and instance_id and schedule_success:
        connection_command = f"aws ssm start-session --target {instance_id} --region {os.environ['AWS_REGION']}"
        success_message = (
            f":white_check_mark: Bastion host `{instance_id}` created successfully for {requesting_user_name}!\n"
            f"It will be automatically destroyed in approximately {lifetime_minutes} minutes.\n"
            f"Connect using:\n```\n{connection_command}\n```\n"
            f"(SessionID: `{session_id}`)"
        )
        log_slack_response_intent(response_url, {'text': success_message})
        # Return success status and details for logging/monitoring
        return {'status': 'success', 'instance_id': instance_id, 'session_id': session_id}
    elif tf_success and instance_id and not schedule_success:
         # Warning message intent logged above. Return status indicates partial success.
         return {'status': 'success_with_warning', 'instance_id': instance_id, 'session_id': session_id, 'message': 'Bastion created, but failed to schedule destruction.'}
    else: # tf_success is False
         # Error message intent logged in Terraform execution block.
         # Return generic error status.
         return {'status': 'error', 'message': 'Bastion creation failed during Terraform execution.'}
