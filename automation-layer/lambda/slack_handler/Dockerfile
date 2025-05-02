# automation-layer/lambda/slack_handler/Dockerfile

# Use the official AWS Lambda Python runtime base image
FROM public.ecr.aws/lambda/python:3.11

# Copy function code and dependencies
COPY requirements.txt ${LAMBDA_TASK_ROOT}/
COPY slack_handler.py ${LAMBDA_TASK_ROOT}/

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Set the CMD to your handler
CMD [ "slack_handler.handler" ]
