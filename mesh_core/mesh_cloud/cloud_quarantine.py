import boto3
import logging
import os
import threading
from datetime import datetime
from dotenv import load_dotenv
import cbor2
import redis
from botocore.exceptions import ClientError
from audit_core.audit_log.qldb_logger import QLDBLogger
from security_core.pqc.dilithium import sign_message
import time
import hashlib

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/cloud_quarantine.log')
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')
QUARANTINE_TABLE = os.getenv('QUARANTINE_TABLE', 'ConnectionQuarantineEvents')
LAMBDA_FUNCTION_NAME = os.getenv('LAMBDA_FUNCTION_NAME', 'ConnectionNodeQuarantine')
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')

class CloudQuarantineManager:
    def __init__(self, region_name=AWS_REGION):
        self.region_name = region_name
        self.lambda_client = boto3.client('lambda', region_name=self.region_name)
        self.dynamodb = boto3.resource('dynamodb', region_name=self.region_name)
        self.quarantine_table = QUARANTINE_TABLE
        self.lock = threading.Lock()
        self.redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)

    def quarantine_node(self, node_id, reason, admin_id="SYSTEM", retries=3):
        """Quarantine a node with DynamoDB logging, Lambda invocation, and QLDB audit."""
        with self.lock:
            if not all([isinstance(node_id, str), node_id.strip(), isinstance(reason, str), reason.strip(), isinstance(admin_id, str), admin_id.strip()]):
                logger.warning(f"Invalid quarantine input: node_id={node_id}, reason={reason}, admin_id={admin_id}")
                return False

            timestamp = datetime.utcnow().isoformat()
            event = {
                'node_id': node_id,
                'reason': reason,
                'admin_id': admin_id,
                'timestamp': timestamp,
                'status': 'QUARANTINED'
            }
            event_hash = hashlib.sha3_512(cbor2.dumps(event)).hexdigest()
            cache_key = f"quarantine_{event_hash}"

            # Check cache to avoid duplicate events
            if self.redis_client.get(cache_key):
                logger.debug(f"Skipping duplicate quarantine for node_id={node_id}")
                return True

            try:
                # Log to DynamoDB with retries
                for attempt in range(retries):
                    try:
                        table = self.dynamodb.Table(self.quarantine_table)
                        table.put_item(Item=event)
                        break
                    except ClientError as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for DynamoDB put: {e}")
                            time.sleep(2 ** attempt)  # Exponential backoff
                        else:
                            logger.error(f"Failed to log quarantine for node_id={node_id} after {retries} attempts: {e}")
                            return False

                # Log to QLDB with Dilithium signature
                event_data = {**event, 'event_hash': event_hash}
                signature = sign_message(cbor2.dumps(event_data))
                QLDBLogger.log_event("quarantine_event", {**event_data, 'signature': signature})

                # Cache event for 300 seconds
                self.redis_client.setex(cache_key, 300, json.dumps(event))

                # Trigger Lambda quarantine
                self._invoke_quarantine_lambda(node_id, reason, retries)

                logger.warning(f"Node {node_id} quarantined: {reason}")
                return True
            except Exception as e:
                logger.error(f"Failed to quarantine node_id={node_id}: {e}")
                return False

    def _invoke_quarantine_lambda(self, node_id, reason, retries=3):
        """Invoke Lambda function to enforce quarantine with retry logic."""
        try:
            payload = {'node_id': node_id, 'reason': reason}
            payload_bytes = cbor2.dumps(payload)
            signature = sign_message(payload_bytes)
            signed_payload = {'data': payload, 'signature': signature}

            for attempt in range(retries):
                try:
                    response = self.lambda_client.invoke(
                        FunctionName=LAMBDA_FUNCTION_NAME,
                        InvocationType='Event',
                        Payload=cbor2.dumps(signed_payload)
                    )
                    # Log to QLDB
                    event_data = {
                        "node_id": node_id,
                        "lambda_function": LAMBDA_FUNCTION_NAME,
                        "signature": signature
                    }
                    QLDBLogger.log_event("quarantine_lambda_invoke", event_data)
                    logger.info(f"Triggered Lambda quarantine for node_id={node_id}")
                    return response
                except ClientError as e:
                    if attempt < retries - 1:
                        logger.warning(f"Retry {attempt + 1}/{retries} for Lambda invoke: {e}")
                        time.sleep(2 ** attempt)  # Exponential backoff
                    else:
                        logger.error(f"Failed to trigger Lambda for node_id={node_id} after {retries} attempts: {e}")
                        return None
        except Exception as e:
            logger.error(f"Failed to invoke Lambda for node_id={node_id}: {e}")
            return None

# Example usage
if __name__ == "__main__":
    manager = CloudQuarantineManager()
    manager.quarantine_node("node-001", "Failed attestation (Truth Beacon)")