import boto3
import json
import logging
import os
import threading
from dotenv import load_dotenv
import cbor2
import redis
from botocore.exceptions import ClientError
from audit_core.audit_log.qldb_logger import QLDBLogger
from security_core.pqc.dilithium import sign_message
import time

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/kinesis_stream.log')
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
KINESIS_STREAM_NAME = os.getenv('KINESIS_STREAM_NAME', 'ConnectionMeshTelemetry')
AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
MAX_BATCH_SIZE = int(os.getenv('KINESIS_MAX_BATCH_SIZE', 500))

class KinesisStream:
    def __init__(self, stream_name=None, region_name=AWS_REGION):
        self.stream_name = stream_name or KINESIS_STREAM_NAME
        self.region_name = region_name
        self.kinesis = boto3.client('kinesis', region_name=self.region_name)
        self.lock = threading.Lock()
        self.redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)

    def put_record(self, data, partition_key, retries=3):
        """Send a single record to Kinesis with PQC signing and retry logic."""
        with self.lock:
            try:
                # Serialize and sign payload
                data_bytes = cbor2.dumps(data)
                signature = sign_message(data_bytes)
                signed_data = {'data': data, 'signature': signature}

                # Publish with retries
                for attempt in range(retries):
                    try:
                        response = self.kinesis.put_record(
                            StreamName=self.stream_name,
                            Data=cbor2.dumps(signed_data),
                            PartitionKey=partition_key
                        )
                        # Log to QLDB
                        event_data = {
                            "stream_name": self.stream_name,
                            "partition_key": partition_key,
                            "data_hash": hashlib.sha3_512(data_bytes).hexdigest(),
                            "signature": signature
                        }
                        QLDBLogger.log_event("kinesis_put_record", event_data)
                        logger.info(f"Sent record to Kinesis: partition_key={partition_key}")
                        return response
                    except ClientError as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for partition_key={partition_key}: {e}")
                            time.sleep(2 ** attempt)  # Exponential backoff
                        else:
                            logger.error(f"Failed to put record to Kinesis after {retries} attempts: {e}")
                            return None
            except Exception as e:
                logger.error(f"Error putting record to Kinesis: {e}")
                return None

    def batch_put_records(self, records, retries=3):
        """Send a batch of records to Kinesis with caching and partial failure handling."""
        with self.lock:
            if not records:
                logger.warning("Empty batch provided")
                return None
            if len(records) > MAX_BATCH_SIZE:
                logger.error(f"Batch size {len(records)} exceeds maximum {MAX_BATCH_SIZE}")
                return None

            cache_key = f"kinesis_batch_{hashlib.sha3_512(cbor2.dumps(records)).hexdigest()}"
            cached_response = self.redis_client.get(cache_key)
            if cached_response:
                logger.debug(f"Returning cached batch response for {len(records)} records")
                return json.loads(cached_response)

            try:
                # Prepare records with signatures
                kinesis_records = []
                for record in records:
                    data = record['data']
                    partition_key = record['partition_key']
                    data_bytes = cbor2.dumps(data)
                    signature = sign_message(data_bytes)
                    signed_data = {'data': data, 'signature': signature}
                    kinesis_records.append({
                        'Data': cbor2.dumps(signed_data),
                        'PartitionKey': partition_key
                    })

                # Publish with retries
                for attempt in range(retries):
                    try:
                        response = self.kinesis.put_records(
                            StreamName=self.stream_name,
                            Records=kinesis_records
                        )
                        # Check for failed records
                        failed_count = response.get('FailedRecordCount', 0)
                        if failed_count > 0:
                            logger.warning(f"Failed to put {failed_count} records in batch")
                            # Optionally retry failed records (simplified here)
                        
                        # Log to QLDB
                        event_data = {
                            "stream_name": self.stream_name,
                            "record_count": len(records),
                            "failed_count": failed_count,
                            "signature": sign_message(cbor2.dumps([r['Data'] for r in kinesis_records]))
                        }
                        QLDBLogger.log_event("kinesis_batch_put", event_data)
                        
                        # Cache response for 60 seconds
                        self.redis_client.setex(cache_key, 60, json.dumps(response))
                        logger.info(f"Batch sent to Kinesis: {len(records)} records, {failed_count} failed")
                        return response
                    except ClientError as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for batch: {e}")
                            time.sleep(2 ** attempt)  # Exponential backoff
                        else:
                            logger.error(f"Failed to put batch to Kinesis after {retries} attempts: {e}")
                            return None
            except Exception as e:
                logger.error(f"Batch put to Kinesis failed: {e}")
                return None

# Example usage
if __name__ == "__main__":
    ks = KinesisStream()
    ks.put_record({"node_id": "node-001", "latency": 48}, "node-001")
    ks.batch_put_records([
        {"data": {"node_id": "node-001", "latency": 48}, "partition_key": "node-001"},
        {"data": {"node_id": "node-002", "latency": 52}, "partition_key": "node-002"}
    ])