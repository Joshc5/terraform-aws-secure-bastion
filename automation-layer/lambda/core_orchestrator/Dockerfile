# automation-layer/lambda/core_orchestrator/Dockerfile
# Also used for destroy_handler (adjust path in main.tf if separating)

# Use the official AWS Lambda Python runtime base image
FROM public.ecr.aws/lambda/python:3.11 as base

# --- Build stage for Terraform ---
FROM alpine:latest as terraform_builder
ARG TERRAFORM_VERSION=1.8.4 # Specify desired Terraform version (Updated to a later 1.8.x patch)
ARG TARGETARCH # Automatically set by buildx to e.g., amd64, arm64

# Install dependencies needed to download and unzip
RUN apk add --no-cache curl unzip

# Download and install Terraform
RUN curl -Lo terraform.zip "https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_${TARGETARCH}.zip" && \
    unzip terraform.zip -d /usr/local/bin && \
    rm terraform.zip && \
    chmod +x /usr/local/bin/terraform

# --- Final stage ---
FROM base

# Copy Terraform binary from the builder stage
COPY --from=terraform_builder /usr/local/bin/terraform /usr/local/bin/terraform

# Copy function code and dependencies for core_orchestrator
# If separating Dockerfiles, adjust paths accordingly
COPY lambda/core_orchestrator/requirements.txt ${LAMBDA_TASK_ROOT}/
COPY lambda/core_orchestrator/orchestrator.py ${LAMBDA_TASK_ROOT}/

# Copy function code for destroy_handler
COPY lambda/destroy_handler/requirements.txt ${LAMBDA_TASK_ROOT}/destroy_requirements.txt
COPY lambda/destroy_handler/destroyer.py ${LAMBDA_TASK_ROOT}/

# Install Python dependencies (requests for orchestrator, none for destroyer)
# Install from core_orchestrator requirements first
RUN pip install --no-cache-dir -r requirements.txt
# If destroy_requirements.txt had anything, install it here too
# RUN pip install --no-cache-dir -r destroy_requirements.txt

# Copy the bastion module code into the container
# Assumes the bastion module is in the parent directory relative to the Docker context
# Adjust the source path if your directory structure is different
COPY ../ ${LAMBDA_TASK_ROOT}/bastion_module/

# Set the default CMD to the orchestrator handler.
# The Lambda function definition in Terraform MUST override this CMD
# for the destroy_handler function deployment, pointing it to "destroyer.handler".
# Example CMD override in Terraform aws_lambda_function resource:
# image_config {
#   command = ["destroyer.handler"]
# }
CMD [ "orchestrator.handler" ]
