import boto3
import json
import datetime
import logging
import threading
from dotenv import load_dotenv
import os
import redis
import cbor2
import hashlib
import time
import orjson
from botocore.exceptions import ClientError
from audit_core.audit_log.qldb_logger import QLDBLogger
from security_core.pqc.dilithium import DilithiumSigner
from security_core.zk_snark.zkp import generate_zkp, verify_zkp
from jsonschema import validate, ValidationError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/public_feed.log')
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
S3_BUCKET = os.getenv("PUBLIC_FEED_BUCKET", "connection-byjamie-public-feed")
FEED_PREFIX = os.getenv("FEED_PREFIX", "events/")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
IOT_TOPIC_PREFIX = os.getenv("IOT_TOPIC_PREFIX", "mesh")

# JSON schema for event records
EVENT_SCHEMA = {
    "type": "object",
    "properties": {
        "timestamp": {"type": "string"},
        "event_type": {"type": "string"},
        "event_data": {"type": "object"},
        "signature": {"type": "string"},
        "public_key": {"type": "string"}
    },
    "required": ["timestamp", "event_type", "event_data"]
}

class PublicFeed:
    """
    Publishes sanitized audit events to a public S3 bucket with PQC signatures.
    Supports event publishing and retrieval with secure integration.
    """

    def __init__(self, bucket=S3_BUCKET, prefix=FEED_PREFIX):
        self.s3 = boto3.client("s3", region_name=AWS_REGION)
        self.bucket = bucket
        self.prefix = prefix.rstrip("/") + "/"
        self.lock = threading.Lock()
        self.redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
        self.iot_client = boto3.client("iot-data", region_name=AWS_REGION)
        self.signer = DilithiumSigner()
        self.logger = QLDBLogger()

    def _sanitize_event_data(self, event_data):
        """Remove sensitive fields from event data."""
        sanitized = event_data.copy()
        sensitive_keys = ["private_key", "password", "secret", "witness", "token"]
        for key in sensitive_keys:
            if key in sanitized:
                sanitized[key] = "[REDACTED]"
        return sanitized

    def publish_event(self, event_type, event_data, retries=3):
        """
        Write a sanitized event to the public S3 audit feed with PQC signatures.
        """
        with self.lock:
            if not isinstance(event_type, str) or not event_type.strip() or not isinstance(event_data, dict):
                logger.warning(f"Invalid input: event_type={event_type}, event_data={event_data}")
                raise ValueError("Invalid event_type or event_data")

            try:
                timestamp = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
                sanitized_data = self._sanitize_event_data(event_data)
                event_record = {
                    "timestamp": timestamp,
                    "event_type": event_type,
                    "event_data": sanitized_data
                }

                # Validate event record
                validate(instance=event_record, schema=EVENT_SCHEMA)

                # Generate Dilithium signature
                event_bytes = cbor2.dumps(event_record)
                pub_key, priv_key = self.signer.keygen()
                signature = self.signer.sign(event_bytes, priv_key)
                event_record["signature"] = signature
                event_record["public_key"] = pub_key

                # Generate ZKP for event integrity
                event_hash = hashlib.sha3_512(event_bytes).hexdigest()
                zkp = generate_zkp(event_hash)
                if not verify_zkp(event_hash, zkp):
                    logger.warning(f"ZKP verification failed for event_hash={event_hash[:16]}...")
                    raise RuntimeError("Event integrity verification failed")
                event_record["zkp"] = zkp

                key = f"{self.prefix}{timestamp}-{event_type}.json"
                cache_key = f"public_feed_{event_hash}"

                # Check cache to avoid duplicate writes
                cached_key = self.redis_client.get(cache_key)
                if cached_key:
                    logger.debug(f"Returning cached S3 key for event_hash={event_hash[:16]}...")
                    return cached_key

                for attempt in range(retries):
                    try:
                        # Write to S3
                        self.s3.put_object(
                            Bucket=self.bucket,
                            Key=key,
                            Body=orjson.dumps(event_record),
                            ContentType="application/json",
                            ACL="public-read"
                        )

                        # Log to QLDB
                        qldb_event_data = {
                            "event_hash": event_hash,
                            "event_type": event_type,
                            "s3_key": key,
                            "signature": sign_message(cbor2.dumps({"event_hash": event_hash}))
                        }
                        self.logger.log_event("public_feed_publish", qldb_event_data)

                        # Publish to AWS IoT
                        payload = {
                            "event_hash": event_hash,
                            "event_type": event_type,
                            "s3_key": key,
                            "public_key": pub_key[:16]
                        }
                        payload_bytes = cbor2.dumps(payload)
                        signature = sign_message(payload_bytes)
                        signed_payload = {'data': payload, 'signature': signature}

                        self.iot_client.publish(
                            topic=f"{IOT_TOPIC_PREFIX}/public_feed/event",
                            qos=1,
                            payload=cbor2.dumps(signed_payload)
                        )

                        # Cache S3 key for 300 seconds
                        self.redis_client.setex(cache_key, 300, key)

                        logger.info(f"Published event to S3: event_type={event_type}, s3_key={key}")
                        return key
                    except ClientError as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for publish_event: {e}")
                            time.sleep(2 ** attempt)
                        else:
                            logger.error(f"Failed to publish event after {retries} attempts: {e}")
                            raise
            except ValidationError as e:
                logger.error(f"Invalid event record schema: {e}")
                raise
            except Exception as e:
                logger.error(f"Failed to publish event: {e}")
                raise

    def get_public_events(self, limit=100, prefix=None, retries=3) -> list:
        """
        Retrieve recent public events from S3 with caching.
        """
        with self.lock:
            try:
                prefix = prefix or self.prefix
                cache_key = f"public_feed_events_{hashlib.sha3_512(prefix.encode()).hexdigest()}_{limit}"
                cached_events = self.redis_client.get(cache_key)
                if cached_events:
                    logger.debug("Returning cached public events")
                    return json.loads(cached_events)

                for attempt in range(retries):
                    try:
                        response = self.s3.list_objects_v2(
                            Bucket=self.bucket,
                            Prefix=prefix,
                            MaxKeys=limit
                        )
                        events = []
                        for obj in response.get('Contents', []):
                            obj_response = self.s3.get_object(Bucket=self.bucket, Key=obj['Key'])
                            event = orjson.loads(obj_response['Body'].read())

                            # Verify Dilithium signature
                            event_data = {
                                "timestamp": event["timestamp"],
                                "event_type": event["event_type"],
                                "event_data": event["event_data"]
                            }
                            event_bytes = cbor2.dumps(event_data)
                            if self.signer.verify(event_bytes, event["signature"], event["public_key"]):
                                event_hash = hashlib.sha3_512(event_bytes).hexdigest()
                                if verify_zkp(event_hash, event["zkp"]):
                                    events.append(event)
                                else:
                                    logger.warning(f"ZKP verification failed for event_key={obj['Key']}")
                            else:
                                logger.warning(f"Signature verification failed for event_key={obj['Key']}")

                        # Log to QLDB
                        event_data = {
                            "query_hash": hashlib.sha3_512(prefix.encode()).hexdigest(),
                            "event_count": len(events),
                            "signature": sign_message(cbor2.dumps({"query_hash": hashlib.sha3_512(prefix.encode()).hexdigest()}))
                        }
                        self.logger.log_event("public_feed_get", event_data)

                        # Cache events for 60 seconds
                        self.redis_client.setex(cache_key, 60, json.dumps(events))

                        # Publish to AWS IoT
                        payload = {
                            "query_hash": event_data["query_hash"],
                            "event_count": len(events)
                        }
                        payload_bytes = cbor2.dumps(payload)
                        signature = sign_message(payload_bytes)
                        signed_payload = {'data': payload, 'signature': signature}

                        self.iot_client.publish(
                            topic=f"{IOT_TOPIC_PREFIX}/public_feed/query",
                            qos=1,
                            payload=cbor2.dumps(signed_payload)
                        )

                        logger.info(f"Retrieved {len(events)} public events from S3")
                        return events
                    except ClientError as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for get_public_events: {e}")
                            time.sleep(2 ** attempt)
                        else:
                            logger.error(f"Failed to retrieve events after {retries} attempts: {e}")
                            return []
            except Exception as e:
                logger.error(f"Failed to retrieve public events: {e}")
                return []

# Example usage
if __name__ == "__main__":
    feed = PublicFeed()
    key = feed.publish_event(
        "node_attested",
        {"node_id": "mesh123", "status": "attested", "proof": "snark:xyz"}
    )
    print(f"Published event to S3: {key}")
    events = feed.get_public_events(limit=10)
    print(f"Retrieved {len(events)} public events")