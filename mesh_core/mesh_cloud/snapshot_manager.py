import boto3
import json
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
        logging.FileHandler('logs/snapshot_manager.log')
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')
SNAPSHOT_BUCKET = os.getenv('SNAPSHOT_BUCKET', 'connection-snapshots')
SNAPSHOT_PREFIX = os.getenv('SNAPSHOT_PREFIX', 'snapshots/')
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')

class SnapshotManager:
    def __init__(self, bucket_name=None, prefix=SNAPSHOT_PREFIX):
        self.s3 = boto3.client('s3', region_name=AWS_REGION)
        self.bucket = bucket_name or SNAPSHOT_BUCKET
        self.prefix = prefix.rstrip('/') + '/'
        self.lock = threading.Lock()
        self.redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)

    def create_snapshot(self, node_id, data, retries=3):
        """Create and upload a snapshot for a node with PQC signing and retry logic."""
        with self.lock:
            if not isinstance(node_id, str) or not node_id.strip():
                logger.warning(f"Invalid node_id: {node_id}")
                return None
            if not isinstance(data, (str, dict)):
                logger.warning(f"Invalid data type: {type(data)}")
                return None

            timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
            key = f"{self.prefix}{node_id}_{timestamp}.cbor"
            try:
                # Serialize and sign data
                data_dict = json.loads(data) if isinstance(data, str) else data
                data_bytes = cbor2.dumps(data_dict)
                signature = sign_message(data_bytes)
                signed_data = {'data': data_dict, 'signature': signature}

                # Upload with retries
                for attempt in range(retries):
                    try:
                        self.s3.put_object(
                            Bucket=self.bucket,
                            Key=key,
                            Body=cbor2.dumps(signed_data),
                            ServerSideEncryption='AES256'
                        )
                        # Log to QLDB
                        event_data = {
                            "node_id": node_id,
                            "key": key,
                            "data_hash": hashlib.sha3_512(data_bytes).hexdigest(),
                            "signature": signature
                        }
                        QLDBLogger.log_event("snapshot_create", event_data)
                        logger.info(f"Snapshot created for node_id={node_id} at {key}")
                        return key
                    except ClientError as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for snapshot create {key}: {e}")
                            time.sleep(2 ** attempt)  # Exponential backoff
                        else:
                            logger.error(f"Snapshot creation failed for node_id={node_id} after {retries} attempts: {e}")
                            return None
            except Exception as e:
                logger.error(f"Snapshot creation failed for node_id={node_id}: {e}")
                return None

    def restore_snapshot(self, key, retries=3):
        """Restore a snapshot from S3 with retry logic."""
        with self.lock:
            if not isinstance(key, str) or not key.startswith(self.prefix):
                logger.warning(f"Invalid snapshot key: {key}")
                return None

            try:
                # Retrieve with retries
                for attempt in range(retries):
                    try:
                        response = self.s3.get_object(Bucket=self.bucket, Key=key)
                        signed_data = cbor2.loads(response['Body'].read())
                        data = signed_data['data']
                        signature = signed_data['signature']

                        # Verify signature (assumed Dilithium)
                        if not verify_signature(cbor2.dumps(data), signature, key.split('_')[0]):
                            logger.error(f"Invalid signature for snapshot key={key}")
                            return None

                        # Log to QLDB
                        event_data = {
                            "node_id": key.split('_')[0],
                            "key": key,
                            "data_hash": hashlib.sha3_512(cbor2.dumps(data)).hexdigest()
                        }
                        QLDBLogger.log_event("snapshot_restore", event_data)
                        logger.info(f"Snapshot {key} restored successfully")
                        return json.dumps(data)  # Return as JSON string for compatibility
                    except ClientError as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for snapshot restore {key}: {e}")
                            time.sleep(2 ** attempt)  # Exponential backoff
                        else:
                            logger.error(f"Snapshot restoration failed for key={key} after {retries} attempts: {e}")
                            return None
            except Exception as e:
                logger.error(f"Snapshot restoration failed for key={key}: {e}")
                return None

    def list_snapshots(self, node_id=None, retries=3):
        """List snapshots with caching and retry logic."""
        with self.lock:
            cache_key = f"snapshots_{node_id or 'all'}"
            cached_snapshots = self.redis_client.get(cache_key)
            if cached_snapshots:
                logger.debug(f"Returning cached snapshots for node_id={node_id or 'all'}")
                return json.loads(cached_snapshots)

            try:
                prefix = self.prefix
                if node_id:
                    if not isinstance(node_id, str) or not node_id.strip():
                        logger.warning(f"Invalid node_id: {node_id}")
                        return []
                    prefix += f"{node_id}_"

                # List with retries
                for attempt in range(retries):
                    try:
                        response = self.s3.list_objects_v2(Bucket=self.bucket, Prefix=prefix)
                        keys = [obj['Key'] for obj in response.get('Contents', [])]
                        
                        # Log to QLDB
                        event_data = {
                            "node_id": node_id or "all",
                            "snapshot_count": len(keys)
                        }
                        QLDBLogger.log_event("snapshot_list", event_data)
                        
                        # Cache for 300 seconds
                        self.redis_client.setex(cache_key, 300, json.dumps(keys))
                        logger.info(f"Snapshots listed for node_id={node_id or 'all'}: {len(keys)} snapshots")
                        return keys
                    except ClientError as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for snapshot list: {e}")
                            time.sleep(2 ** attempt)  # Exponential backoff
                        else:
                            logger.error(f"Listing snapshots failed after {retries} attempts: {e}")
                            return []
            except Exception as e:
                logger.error(f"Listing snapshots failed: {e}")
                return []

# Example usage
if __name__ == "__main__":
    sm = SnapshotManager()
    sm.create_snapshot("node-001", '{"state": "healthy"}')
    keys = sm.list_snapshots("node-001")
    if keys:
        sm.restore_snapshot(keys[-1])