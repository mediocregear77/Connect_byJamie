```python
"""
deployment/deploy_utils.py

Deployment utility functions for Connection byJamie.
Automates AWS resource setup, environment validation, and secure deployment flows.
Optimized for security, performance, and auditability for AWS Breaking Barriers Hackathon 2025.
"""

import os
import subprocess
import sys
import yaml
import boto3
import botocore
import logging
from pathlib import Path
from botocore.exceptions import ClientError
from retrying import retry
from dotenv import load_dotenv
from audit_core.audit_log.qldb_logger import QLDBLogger
from security_core.pqc.dilithium import DilithiumSigner
import hashlib
import cbor2
import time

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/deploy_utils.log')
    ]
)
logger = logging.getLogger("deploy_utils")

# Load environment variables
load_dotenv()

# AWS configuration
AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')
KMS_KEY_ID = os.getenv('KMS_KEY_ID', '')

def load_yaml_config(path: str) -> dict:
    """
    Load and validate a YAML configuration file.

    Args:
        path (str): Path to the YAML file.

    Returns:
        dict: Parsed YAML configuration.

    Raises:
        FileNotFoundError: If the file does not exist.
        yaml.YAMLError: If the YAML is invalid.
    """
    try:
        path = Path(path)
        if not path.is_file():
            logger.error(f"Configuration file not found: {path}")
            raise FileNotFoundError(f"File not found: {path}")
        with path.open("r") as f:
            config = yaml.safe_load(f)
        if not isinstance(config, dict):
            logger.error(f"Invalid YAML configuration: {path}")
            raise ValueError("Configuration must be a dictionary")
        logger.info(f"Loaded configuration: {path}")
        return config
    except (FileNotFoundError, yaml.YAMLError, ValueError) as e:
        logger.error(f"Failed to load YAML config: {e}")
        raise

def run_shell(cmd: str, exit_on_error: bool = True) -> subprocess.CompletedProcess:
    """
    Run a shell command with output logging.

    Args:
        cmd (str): Command to execute.
        exit_on_error (bool): Exit on command failure if True.

    Returns:
        subprocess.CompletedProcess: Command execution result.

    Raises:
        subprocess.CalledProcessError: If the command fails and exit_on_error is True.
    """
    logger.info(f"Executing shell command: {cmd}")
    try:
        process = subprocess.run(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
        logger.info(f"Command output: {process.stdout.strip()}")
        return process
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed: {cmd}\nError: {e.stderr.strip()}")
        if exit_on_error:
            sys.exit(1)
        raise

@retry(stop_max_attempt_number=3, wait_exponential_multiplier=1000, wait_exponential_max=10000)
def validate_aws_credentials() -> bool:
    """
    Validate AWS credentials and configuration.

    Returns:
        bool: True if credentials are valid.

    Raises:
        ClientError: If AWS credentials are invalid or misconfigured.
    """
    try:
        session = boto3.Session(region_name=AWS_REGION)
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        logger.info(f"AWS Account: {identity['Account']} | UserId: {identity['UserId']} | ARN: {identity['Arn']}")
        return True
    except ClientError as e:
        logger.error(f"AWS credentials validation failed: {e}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error during AWS credentials validation: {e}")
        sys.exit(1)

@retry(stop_max_attempt_number=3, wait_exponential_multiplier=1000, wait_exponential_max=10000)
def deploy_cloudformation(stack_name: str, template_path: str, parameters: dict = None) -> dict:
    """
    Deploy or update a CloudFormation stack with audit logging.

    Args:
        stack_name (str): Name of the CloudFormation stack.
        template_path (str): Path to the CloudFormation template.
        parameters (dict, optional): Stack parameters.

    Returns:
        dict: Deployment result with stack ID and status.

    Raises:
        ClientError: If the stack operation fails.
        FileNotFoundError: If the template file is missing.
    """
    try:
        cf = boto3.client("cloudformation", region_name=AWS_REGION)
        template_path = Path(template_path)
        if not template_path.is_file():
            logger.error(f"CloudFormation template not found: {template_path}")
            raise FileNotFoundError(f"Template not found: {template_path}")

        with template_path.open("r") as f:
            template_body = f.read()

        # Generate Dilithium signature for template
        signer = DilithiumSigner()
        template_hash = hashlib.sha3_512(template_body.encode()).hexdigest()
        pub_key, priv_key = signer.keygen()
        signature = signer.sign(template_hash.encode(), priv_key)

        # Check if stack exists
        try:
            cf.describe_stacks(StackName=stack_name)
            action = "update_stack"
            logger.info(f"Updating existing stack: {stack_name}")
        except cf.exceptions.ClientError as e:
            if "does not exist" in str(e):
                action = "create_stack"
                logger.info(f"Creating new stack: {stack_name}")
            else:
                raise

        params = {
            "StackName": stack_name,
            "TemplateBody": template_body,
            "Capabilities": ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM", "CAPABILITY_AUTO_EXPAND"]
        }
        if parameters:
            params["Parameters"] = [{"ParameterKey": k, "ParameterValue": str(v)} for k, v in parameters.items()]

        # Deploy stack
        if action == "create_stack":
            response = cf.create_stack(**params)
        else:
            try:
                response = cf.update_stack(**params)
            except cf.exceptions.ClientError as e:
                if "No updates are to be performed" in str(e):
                    logger.info(f"No updates needed for stack: {stack_name}")
                    return {"stack_id": stack_name, "status": "NO_CHANGES"}
                raise

        stack_id = response["StackId"]
        logger.info(f"Stack {action} initiated: {stack_id}")

        # Log to QLDB
        logger_instance = QLDBLogger()
        qldb_event_data = {
            "stack_id": stack_id,
            "stack_name": stack_name,
            "template_hash": template_hash,
            "action": action,
            "signature": signature,
            "public_key": pub_key
        }
        logger_instance.log_event("cloudformation_deployment", qldb_event_data)

        # Publish to AWS IoT
        iot_client = boto3.client("iot-data", region_name=AWS_REGION)
        payload = {
            "stack_id": stack_id,
            "stack_name": stack_name,
            "template_hash": template_hash[:16],
            "action": action
        }
        payload_bytes = cbor2.dumps(payload)
        signature = signer.sign(payload_bytes, priv_key)
        signed_payload = {'data': payload, 'signature': signature}

        try:
            iot_client.publish(
                topic=f"{os.getenv('IOT_TOPIC_PREFIX', 'mesh')}/deployment/cloudformation",
                qos=1,
                payload=cbor2.dumps(signed_payload)
            )
        except ClientError as e:
            logger.warning(f"IoT publish error: {e}")

        return {"stack_id": stack_id, "status": "INITIATED"}
    except Exception as e:
        logger.error(f"Failed to deploy CloudFormation stack {stack_name}: {e}")
        raise

@retry(stop_max_attempt_number=3, wait_exponential_multiplier=1000, wait_exponential_max=10000)
def sync_static_assets(local_dir: str, s3_bucket: str, s3_prefix: str = "static/") -> None:
    """
    Sync local static assets to S3 with KMS encryption and audit logging.

    Args:
        local_dir (str): Local directory containing static assets.
        s3_bucket (str): S3 bucket name.
        s3_prefix (str): S3 prefix for uploaded files.

    Raises:
        ClientError: If S3 upload fails.
        FileNotFoundError: If the local directory is missing.
    """
    try:
        s3 = boto3.client("s3", region_name=AWS_REGION)
        local_dir = Path(local_dir)
        if not local_dir.is_dir():
            logger.error(f"Static assets directory not found: {local_dir}")
            raise FileNotFoundError(f"Directory not found: {local_dir}")

        signer = DilithiumSigner()
        pub_key, priv_key = signer.keygen()
        uploaded_files = []

        for dirpath, _, filenames in os.walk(local_dir):
            for filename in filenames:
                local_file = Path(dirpath) / filename
                key = os.path.join(s3_prefix, os.path.relpath(local_file, local_dir)).replace("\\", "/")
                logger.info(f"Uploading {local_file} to s3://{s3_bucket}/{key}")

                # Calculate file hash
                with local_file.open("rb") as f:
                    file_content = f.read()
                file_hash = hashlib.sha3_512(file_content).hexdigest()

                # Upload with KMS encryption
                s3.upload_file(
                    str(local_file),
                    s3_bucket,
                    key,
                    ExtraArgs={
                        'ServerSideEncryption': 'aws:kms',
                        'SSEKMSKeyId': KMS_KEY_ID,
                        'ACL': 'public-read'
                    }
                )
                uploaded_files.append({"file": key, "hash": file_hash})

        # Log to QLDB
        logger_instance = QLDBLogger()
        batch_hash = hashlib.sha3_512(orjson.dumps(uploaded_files)).hexdigest()
        qldb_event_data = {
            "batch_hash": batch_hash,
            "file_count": len(uploaded_files),
            "s3_bucket": s3_bucket,
            "signature": signer.sign(batch_hash.encode(), priv_key),
            "public_key": pub_key
        }
        logger_instance.log_event("s3_asset_sync", qldb_event_data)

        # Publish to AWS IoT
        iot_client = boto3.client("iot-data", region_name=AWS_REGION)
        payload = {
            "batch_hash": batch_hash[:16],
            "file_count": len(uploaded_files),
            "s3_bucket": s3_bucket
        }
        payload_bytes = cbor2.dumps(payload)
        signature = signer.sign(payload_bytes, priv_key)
        signed_payload = {'data': payload, 'signature': signature}

        try:
            iot_client.publish(
                topic=f"{os.getenv('IOT_TOPIC_PREFIX', 'mesh')}/deployment/s3_sync",
                qos=1,
                payload=cbor2.dumps(signed_payload)
            )
        except ClientError as e:
            logger.warning(f"IoT publish error: {e}")

        logger.info(f"Synced {len(uploaded_files)} static assets to s3://{s3_bucket}/{s3_prefix}")
    except Exception as e:
        logger.error(f"Failed to sync static assets to S3: {e}")
        raise

def main():
    """
    Main deployment function for Connection byJamie.
    Validates AWS credentials, deploys CloudFormation stack, and syncs static assets.
    """
    try:
        # Validate AWS credentials
        validate_aws_credentials()

        # Load configuration
        config_path = Path("data/config/mesh_settings.yaml")
        config = load_yaml_config(config_path)

        # Deploy CloudFormation stack
        stack_name = f"ConnectionByJamie-{os.getenv('ENVIRONMENT', 'prod')}"
        template_path = Path("deployment/aws_deploy.yaml")
        parameters = {
            "Environment": os.getenv('ENVIRONMENT', 'prod'),
            "AWSAccountId": boto3.client("sts").get_caller_identity()["Account"],
            "KMSKeyArn": KMS_KEY_ID,
            "FabricNetworkId": os.getenv('FABRIC_NETWORK_ID', 'n-xxxxxxxx')
        }
        deploy_cloudformation(stack_name, template_path, parameters)

        # Sync static assets
        static_dir = Path("admin_core/admin_console/static")
        s3_bucket = config.get("s3_static_bucket", f"connection-byjamie-{os.getenv('ENVIRONMENT', 'prod')}-data")
        if s3_bucket:
            sync_static_assets(static_dir, s3_bucket)

        logger.info("Deployment completed successfully")
    except Exception as e:
        logger.error(f"Deployment failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
```