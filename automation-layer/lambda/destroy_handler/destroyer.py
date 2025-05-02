# automation-layer/lambda/destroy_handler/destroyer.py

import json
import os
import logging
import subprocess
import tempfile
import shutil

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Environment variables
TF_STATE_BUCKET = os.environ['TF_STATE_BUCKET']

# --- Helper Function (Similar to core_orchestrator) ---

def run_terraform_destroy(working_dir, session_id, state_key):
    """Runs terraform init and destroy using subprocess."""
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
    logger.info(f"Created backend override file for destroy at {backend_file_path}")

    base_command = ["terraform", f"-chdir={working_dir}"]
    init_command = base_command + ["init", "-no-color", "-input=false"]
    destroy_command = base_command + ["destroy", "-auto-approve", "-no-color", "-input=false"]

    try:
        logger.info(f"Running Terraform init for destroy: {' '.join(init_command)}")
        init_process = subprocess.run(init_command, capture_output=True, text=True, check=True, env=env)
        logger.info("Terraform init stdout:\n" + init_process.stdout)
        logger.info("Terraform init stderr:\n" + init_process.stderr)

        logger.info(f"Running Terraform destroy: {' '.join(destroy_command)}")
        process = subprocess.run(destroy_command, capture_output=True, text=True, check=True, env=env)
        logger.info("Terraform destroy stdout:\n" + process.stdout)
        logger.info("Terraform destroy stderr:\n" + process.stderr)
        return True, None # Success
    except subprocess.CalledProcessError as e:
        logger.error(f"Terraform destroy command failed: {e}")
        logger.error("Terraform stdout:\n" + e.stdout)
        logger.error("Terraform stderr:\n" + e.stderr)
        return False, str(e) # Failure
    finally:
        # Clean up backend override file
        if os.path.exists(backend_file_path):
            os.remove(backend_file_path)

# --- Main Handler ---

def handler(event, context):
    """
    Handles invocation from EventBridge Scheduler to destroy bastion resources.
    """
    logger.info(f"Received event: {json.dumps(event)}")

    # --- Input Validation ---
    try:
        # EventBridge payload contains the 'Input' from the schedule
        if isinstance(event.get('detail'), dict): # Check if detail is present (might vary based on trigger source slightly)
             payload = json.loads(event['detail'].get('input', '{}'))
        else: # Direct invocation or different event structure
             payload = event # Assume event itself is the payload

        session_id = payload['SessionID']
        if not session_id:
            raise ValueError("Missing 'SessionID' in event payload.")
        logger.info(f"Received request to destroy bastion for SessionID: {session_id}")

    except (KeyError, ValueError, TypeError, json.JSONDecodeError) as e:
        logger.error(f"Invalid input payload for destroy handler: {e}")
        # No easy way to report back to user here, just log the error.
        # Consider sending to a dead-letter queue or CloudWatch alarm.
        return {'status': 'error', 'message': f"Invalid input payload: {e}"}

    # --- Terraform Destroy Execution ---
    tf_dir = None
    destroy_success = False
    error_message = None

    try:
        # Create a temporary directory
        # Note: We only need the backend config, not the module code for destroy
        tf_dir = tempfile.mkdtemp()
        logger.info(f"Created temporary Terraform directory for destroy: {tf_dir}")

        # Define Terraform state key
        tf_state_key = f"bastion-state/{session_id}.tfstate"

        # Run Terraform Destroy
        destroy_success, error_message = run_terraform_destroy(tf_dir, session_id, tf_state_key)

        if destroy_success:
            logger.info(f"Terraform destroy successful for SessionID: {session_id}")
        else:
            logger.error(f"Terraform destroy failed for SessionID: {session_id}. Error: {error_message}")
            # Consider alerting mechanism here

    except Exception as e:
        logger.error(f"Unhandled error during Terraform destroy execution for SessionID {session_id}: {e}")
        error_message = str(e)
        # Consider alerting mechanism here
    finally:
        # Clean up the temporary directory
        if tf_dir and os.path.exists(tf_dir):
            logger.info(f"Cleaning up temporary directory: {tf_dir}")
            shutil.rmtree(tf_dir)

    # Return status (mainly for logging/monitoring)
    if destroy_success:
        return {'status': 'success', 'session_id': session_id}
    else:
        return {'status': 'error', 'session_id': session_id, 'message': error_message or "Destroy failed."}
