# automation-layer/lambda/slack_handler/slack_handler.py

import json
import os
import logging
import hmac
import hashlib
import time
from urllib.parse import parse_qs
import boto3
import requests # For sending response_url messages

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Environment variables (passed from Terraform)
CORE_ORCHESTRATOR_FUNC_NAME = os.environ['CORE_ORCHESTRATOR_FUNC_NAME']
AUTH_USER_SSM_PARAM = os.environ['AUTH_USER_SSM_PARAM']
SLACK_SIGNING_SECRET_ARN = os.environ['SLACK_SIGNING_SECRET_ARN']
SLACK_BOT_TOKEN_SECRET_ARN = os.environ.get('SLACK_BOT_TOKEN_SECRET_ARN') # Optional, for richer messages

# Initialize AWS clients (cached outside handler)
secrets_manager = boto3.client('secretsmanager')
ssm = boto3.client('ssm')
lambda_client = boto3.client('lambda')

# --- Global cache for secrets & config ---
slack_signing_secret = None
slack_bot_token = None # Optional bot token
authorized_user_list = None
# Define allowed instance types and max lifetime for validation
allowed_instance_types = ['t3.micro', 't3.small', 't3.medium']
max_lifetime_minutes = 480 # Max lifetime (minutes)

def load_config_and_secrets():
    """
    Retrieves Slack secrets and authorized users list from AWS, caching them globally.
    Returns True on success, False on failure.
    """
    global slack_signing_secret, slack_bot_token, authorized_user_list
    # Check if already loaded (avoid redundant calls)
    if slack_signing_secret and authorized_user_list is not None: # Bot token is optional
        return True

    # Fetch secrets
    try:
        logger.info(f"Fetching Slack signing secret from ARN: {SLACK_SIGNING_SECRET_ARN}")
        # Fetch signing secret only if not already loaded
        if not slack_signing_secret:
            logger.info(f"Fetching Slack signing secret from ARN: {SLACK_SIGNING_SECRET_ARN}")
            secret_value = secrets_manager.get_secret_value(SecretId=SLACK_SIGNING_SECRET_ARN)
            slack_signing_secret = secret_value['SecretString']
            logger.info("Successfully fetched Slack signing secret.")

        # Fetch bot token only if ARN is provided and not already loaded
        if not slack_bot_token and SLACK_BOT_TOKEN_SECRET_ARN:
             logger.info(f"Fetching Slack bot token from ARN: {SLACK_BOT_TOKEN_SECRET_ARN}")
             secret_value = secrets_manager.get_secret_value(SecretId=SLACK_BOT_TOKEN_SECRET_ARN)
             slack_bot_token = secret_value['SecretString']
             logger.info("Successfully fetched Slack bot token.")

    except Exception as e:
        logger.error(f"Error fetching Slack secrets: {e}")
        # Reset on error to force reload next time
        slack_signing_secret = None
        slack_bot_token = None
        return False # Indicate failure

    # Fetch authorized users list only if not already loaded
    try:
        if authorized_user_list is None:
            logger.info(f"Fetching authorized users from SSM parameter: {AUTH_USER_SSM_PARAM}")
            parameter = ssm.get_parameter(Name=AUTH_USER_SSM_PARAM, WithDecryption=False)
            # Ensure value is treated as a list, even if empty or malformed
            user_list_str = parameter.get('Parameter', {}).get('Value', '')
            authorized_user_list = [user.strip() for user in user_list_str.split(',') if user.strip()]
            logger.info(f"Authorized users loaded: {authorized_user_list}")
    except Exception as e:
        logger.error(f"Error fetching authorized users from SSM: {e}")
        authorized_user_list = None # Reset on error
        return False # Indicate failure

    # Check if essential config was loaded
    if not slack_signing_secret or authorized_user_list is None:
        logger.critical("Essential configuration (signing secret or auth list) failed to load.")
        return False

    return True # Success loading all required config

def verify_slack_signature(request_headers, request_body):
    """Verifies the signature of the incoming request from Slack."""
    # Ensure secret is loaded
    if not slack_signing_secret:
        logger.error("Slack signing secret not loaded or available for verification.")
        return False

    timestamp = request_headers.get('x-slack-request-timestamp')
    slack_signature = request_headers.get('x-slack-signature')

    if not timestamp or not slack_signature:
        logger.warning("Missing Slack signature headers.")
        return False

    # Prevent replay attacks
    if abs(time.time() - int(timestamp)) > 60 * 5:
        logger.warning("Slack request timestamp too old.")
        return False

    sig_basestring = f"v0:{timestamp}:{request_body}"
    my_signature = 'v0=' + hmac.new(
        slack_signing_secret.encode('utf-8'),
        sig_basestring.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()

    if hmac.compare_digest(my_signature, slack_signature):
        logger.info("Slack signature verified successfully.")
        return True
    else:
        logger.warning("Slack signature verification failed.")
        return False

# This function is superseded by load_config_and_secrets which caches the list.
# We will use the global authorized_user_list instead.
# def get_authorized_users(): ...

def send_slack_response(response_url, message_payload, is_error=False):
    """
    Sends an asynchronous response back to Slack using the response_url.
    Formats error messages generically to avoid leaking internal details.
    """
    # Generic error message for security
    if is_error:
        safe_payload = {
            "response_type": "ephemeral", # Keep errors private
            "text": ":x: An internal error occurred while processing your request. Please contact the administrator if the issue persists."
        }
        # Log the actual detailed error internally for debugging
        logger.error(f"Sending generic error to Slack. Original details: {message_payload.get('text', 'No text provided')}")
        payload_to_send = safe_payload
    else:
        payload_to_send = message_payload

    try:
        logger.info(f"Sending response to Slack URL: {response_url}")
        response = requests.post(response_url, json=message_payload, headers={'Content-Type': 'application/json'})
        response.raise_for_status() # Raise an exception for bad status codes
        logger.info(f"Slack response status code: {response.status_code}")
    except requests.exceptions.RequestException as e:
        logger.error(f"Error sending response to Slack: {e}")

# --- Main Handler ---

def handler(event, context):
    """
    Handles incoming requests from API Gateway triggered by Slack Slash Command.
    Verifies signature, checks authorization, invokes core orchestrator,
    and sends response to Slack.
    """
    logger.info(f"Received event: {json.dumps(event)}")

    # --- Config & Secret Retrieval ---
    # Load secrets and authorized user list at the start of invocation if not cached
    if not load_config_and_secrets():
         # Log detailed error internally, return generic error to gateway
        logger.critical("Failed to load critical configuration (secrets/auth list). Cannot proceed.")
        # Avoid sending details back to Slack here as we might not have response_url yet
        return {'statusCode': 500, 'body': json.dumps("Configuration Error")}

    # --- Signature Verification (CRITICAL SECURITY STEP) ---
    try:
        headers = event.get('headers', {})
        body = event.get('body', '')
        if not verify_slack_signature(headers, body):
            return {'statusCode': 401, 'body': json.dumps("Unauthorized: Invalid signature")}
    except Exception as e:
        logger.error(f"Error during signature verification: {e}")
        return {'statusCode': 500, 'body': json.dumps("Internal Server Error: Signature check failed")}

    # --- Parse Slack Command ---
    try:
        # Slack sends form-encoded data
        parsed_body = parse_qs(body)
        logger.info(f"Parsed Slack body: {parsed_body}")

        # Extract required fields
        user_id = parsed_body.get('user_id', [None])[0]
        user_name = parsed_body.get('user_name', ['unknown'])[0]
        command = parsed_body.get('command', ['unknown'])[0]
        text = parsed_body.get('text', [''])[0] # User input after the command
        response_url = parsed_body.get('response_url', [None])[0]

        # Basic payload structure validation
        if not user_id or not response_url:
            # Should not happen if signature verification passed, but check defensively
            logger.error("CRITICAL: Missing user_id or response_url after signature verification.")
            return {'statusCode': 400, 'body': json.dumps("Bad Request: Invalid payload structure")}

        # --- Argument Parsing & Validation ---
        args = {}
        lifetime_minutes = None
        instance_type = None
        try:
            # Example parsing: key=value key2=value2
            # More robust parsing might be needed depending on complexity
            if text:
                # Split respecting potential spaces in values if quoted? For now, simple split.
                for item in text.split():
                    if "=" in item:
                        key, value = item.split("=", 1)
                        args[key.lower()] = value # Store keys as lowercase
                    # Handle flags or other formats if needed
            logger.info(f"Parsed command args: {args}")

            # Validate lifetime
            default_lifetime = int(os.environ.get('DEFAULT_LIFETIME_MIN', 240))
            lifetime_str = args.get('lifetime')
            if lifetime_str:
                lifetime_minutes = int(lifetime_str) # Can raise ValueError
                if lifetime_minutes <= 0 or lifetime_minutes > max_lifetime_minutes:
                     raise ValueError(f"Invalid lifetime '{lifetime_str}'. Must be between 1 and {max_lifetime_minutes} minutes.")
            else:
                lifetime_minutes = default_lifetime
            logger.info(f"Using lifetime: {lifetime_minutes} minutes")

            # Validate instance type
            default_instance_type = os.environ.get('BASTION_INSTANCE_TYPE', 't3.micro')
            instance_type = args.get('type', default_instance_type)
            if instance_type not in allowed_instance_types:
                raise ValueError(f"Invalid instance type '{instance_type}'. Allowed types: {', '.join(allowed_instance_types)}")
            logger.info(f"Using instance type: {instance_type}")

            # TODO: Add validation for any other expected arguments from 'text'

        except ValueError as ve: # Catch specific validation errors (int conversion, range check, allowed types)
             logger.warning(f"Invalid arguments provided by user {user_id}: {ve}")
             # Send specific validation error back to user
             send_slack_response(response_url, {'text': f":warning: Invalid input: {ve}"})
             return {'statusCode': 200, 'body': ''} # OK to Slack, user error message sent
        except Exception as e: # Catch broader parsing errors (e.g., split failed)
            logger.error(f"Error parsing arguments from text '{text}': {e}")
            # Send generic parsing error back
            send_slack_response(response_url, {'text': f":x: Error parsing your arguments. Please use format `key=value` (e.g., `lifetime=120 type=t3.small`)."}, is_error=True)
            return {'statusCode': 200, 'body': ''} # OK to Slack, generic error message sent

    except Exception as e:
        # Catch errors during the main parsing block (e.g., accessing parsed_body keys)
        logger.error(f"Unexpected error parsing Slack request body: {e}")
        # Avoid sending detailed errors back to Slack or API Gateway
        return {'statusCode': 400, 'body': json.dumps("Bad Request: Cannot process payload")}

    # --- Authorization Check ---
    # Use the globally loaded list
    if authorized_user_list is None: # Check if loading failed earlier
        logger.error("Authorization list not available.")
        send_slack_response(response_url, {'text': ":x: Internal configuration error preventing authorization check."}, is_error=True)
        return {'statusCode': 200, 'body': ''} # OK to Slack, generic error sent

    if user_id not in authorized_user_list:
        logger.warning(f"User {user_id} ({user_name}) is not authorized (not in SSM list).")
        send_slack_response(response_url, {'text': ":no_entry: You are not authorized to request a bastion host."})
        return {'statusCode': 200, 'body': ''}

    # --- Send Initial Acknowledgment ---
    # Slack requires a response within 3 seconds. Send an immediate ack,
    # then use response_url for follow-ups.
    ack_message = {
        "response_type": "ephemeral", # Only visible to the user
        "text": f":hourglass_flowing_sand: Received request from {user_name}. Processing bastion creation..."
    }
    # We return this directly as the response to API Gateway/Slack
    lambda_response = {'statusCode': 200, 'body': json.dumps(ack_message)}

    # --- Prepare Payload for Core Orchestrator ---
    # Extract necessary info and pass to the next Lambda
    # This needs to align with what the Core Orchestrator expects
    orchestrator_payload = {
        'requesting_user_id': user_id,
        'requesting_user_name': user_name,
        'response_url': response_url,
        'bastion_params': {
            # Use validated parameters
            'lifetime_minutes': lifetime_minutes,
            'instance_type': instance_type,
            # Pass required params from environment (assuming they don't change per request here)
            'vpc_id': os.environ.get('BASTION_VPC_ID'),
            'subnet_id': os.environ.get('BASTION_SUBNET_ID'),
        }
    }

    # --- Invoke Core Orchestrator Asynchronously ---
    try:
        logger.info(f"Invoking Core Orchestrator: {CORE_ORCHESTRATOR_FUNC_NAME}")
        lambda_client.invoke(
            FunctionName=CORE_ORCHESTRATOR_FUNC_NAME,
            InvocationType='Event', # Asynchronous invocation
            Payload=json.dumps(orchestrator_payload)
        )
        logger.info("Core Orchestrator invoked successfully.")
    except Exception as e:
        logger.error(f"Error invoking Core Orchestrator Lambda: {e}")
        # Send generic error message back to Slack via response_url
        send_slack_response(response_url, {'text': f":x: Failed to start bastion creation process."}, is_error=True)
        # The initial ack was already sent, so we just log the error here.

    # Return the initial acknowledgment (lambda_response) to Slack via API Gateway
    return lambda_response
