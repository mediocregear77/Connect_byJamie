import boto3
import datetime
import logging
import threading
from dotenv import load_dotenv
import os
import redis
import cbor2
from botocore.exceptions import ClientError
from audit_core.audit_log.qldb_logger import QLDBLogger
from security_core.pqc.dilithium import DilithiumSigner
from security_core.zk_snark.zkp import generate_zkp, verify_zkp
import hashlib
import time
import json
from jsonschema import validate, ValidationError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/qldb_logger.log')
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
QLDB_LEDGER = os.getenv('QLDB_LEDGER_NAME', 'ConnectionByJamieLedger')
TABLE_NAME = os.getenv('TABLE_NAME', 'AuditEvents')
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')
IOT_TOPIC_PREFIX = os.getenv('IOT_TOPIC_PREFIX', 'mesh')

# JSON schema for event records
EVENT_SCHEMA = {
    "type": "object",
    "properties": {
        "timestamp": {"type": "string"},
        "event_type": {"type": "string"},
        "data": {"type": "object"},
        "user": {"type": "string"}
    },
    "required": ["timestamp", "event_type", "data"]
}

class QLDBLogger:
    """
    Logs audit events to AWS QLDB with PQC signatures and zk-SNARKs.
    Supports event logging and retrieval with secure integration.
    """

    def __init__(self, ledger_name=QLDB_LEDGER, table=TABLE_NAME):
        self.client = boto3.client('qldb-session', region_name=AWS_REGION)
        self.ledger_name = ledger_name
        self.table = table
        self.lock = threading.Lock()
        self.redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
        self.iot_client = boto3.client('iot-data', region_name=AWS_REGION)
        self.signer = DilithiumSigner()
        self.session_token = None

    def _start_session(self, retries=3):
        """Start a QLDB session with retry logic."""
        with self.lock:
            if self.session_token:
                return self.session_token

            for attempt in range(retries):
                try:
                    response = self.client.send_command(
                        StartSession={"LedgerName": self.ledger_name}
                    )
                    self.session_token = response["SessionToken"]
                    logger.debug("Started QLDB session")
                    return self.session_token
                except ClientError as e:
                    if attempt < retries - 1:
                        logger.warning(f"Retry {attempt + 1}/{retries} for QLDB session start: {e}")
                        time.sleep(2 ** attempt)
                    else:
                        logger.error(f"Failed to start QLDB session after {retries} attempts: {e}")
                        raise
            raise RuntimeError("Failed to start QLDB session")

    def _end_session(self):
        """End the current QLDB session."""
        with self.lock:
            if self.session_token:
                try:
                    self.client.send_command(EndSession={}, SessionToken=self.session_token)
                    logger.debug("Ended QLDB session")
                except ClientError as e:
                    logger.warning(f"Failed to end QLDB session: {e}")
                finally:
                    self.session_token = None

    def log_event(self, event_type, data, user=None, retries=3):
        """
        Write an immutable audit event to QLDB with PQC signatures.
        """
        with self.lock:
            if not isinstance(event_type, str) or not event_type.strip() or not isinstance(data, dict):
                logger.warning(f"Invalid input: event_type={event_type}, data={data}")
                raise ValueError("Invalid event_type or data")

            try:
                timestamp = datetime.datetime.utcnow().isoformat() + "Z"
                event_record = {
                    "timestamp": timestamp,
                    "event_type": event_type,
                    "data": data,
                    "user": user or "system"
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

                session_token = self._start_session()
                statement = f"INSERT INTO {self.table} ?"

                for attempt in range(retries):
                    try:
                        response = self.client.send_command(
                            SessionToken=session_token,
                            ExecuteStatement={
                                "Statement": statement,
                                "Parameters": [{"IonBinary": cbor2.dumps(event_record)}]
                            }
                        )
                        event_id = response.get('FirstRecordId', 'unknown')

                        # Log to QLDB (meta-log for operation)
                        meta_event_data = {
                            "event_hash": event_hash,
                            "event_type": event_type,
                            "event_id": event_id,
                            "signature": sign_message(cbor2.dumps({"event_hash": event_hash}))
                        }
                        QLDBLogger.log_event("qldb_log_event", meta_event_data)

                        # Publish to AWS IoT
                        payload = {
                            "event_hash": event_hash,
                            "event_type": event_type,
                            "event_id": event_id
                        }
                        payload_bytes = cbor2.dumps(payload)
                        signature = sign_message(payload_bytes)
                        signed_payload = {'data': payload, 'signature': signature}

                        self.iot_client.publish(
                            topic=f"{IOT_TOPIC_PREFIX}/qldb/event",
                            qos=1,
                            payload=cbor2.dumps(signed_payload)
                        )

                        # Clear Redis cache for recent events
                        self.redis_client.delete("qldb_recent_events")

                        logger.info(f"Logged event to QLDB: event_type={event_type}, event_id={event_id}")
                        return True
                    except ClientError as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for log_event: {e}")
                            time.sleep(2 ** attempt)
                        else:
                            logger.error(f"Failed to log event after {retries} attempts: {e}")
                            return False
                    finally:
                        self._end_session()
            except ValidationError as e:
                logger.error(f"Invalid event record schema: {e}")
                return False
            except Exception as e:
                logger.error(f"QLDB audit log error: {e}")
                self._end_session()
                return False

    def get_recent_events(self, limit=100, retries=3) -> list:
        """
        Retrieve recent audit events from QLDB with caching.
        """
        with self.lock:
            try:
                cache_key = f"qldb_recent_events_{limit}"
                cached_events = self.redis_client.get(cache_key)
                if cached_events:
                    logger.debug("Returning cached QLDB recent events")
                    return json.loads(cached_events)

                session_token = self._start_session()
                statement = f"SELECT * FROM {self.table} ORDER BY timestamp DESC LIMIT ?"

                for attempt in range(retries):
                    try:
                        response = self.client.send_command(
                            SessionToken=session_token,
                            ExecuteStatement={
                                "Statement": statement,
                                "Parameters": [{"int": limit}]
                            }
                        )
                        events = [cbor2.loads(record['IonBinary']) for record in response.get('Records', [])]

                        # Verify signatures and ZKPs
                        valid_events = []
                        for event in events:
                            event_data = {
                                "timestamp": event["timestamp"],
                                "event_type": event["event_type"],
                                "data": event["data"],
                                "user": event.get("user", "system")
                            }
                            event_bytes = cbor2.dumps(event_data)
                            if self.signer.verify(event_bytes, event["signature"], event["public_key"]):
                                event_hash = hashlib.sha3_512(event_bytes).hexdigest()
                                if verify_zkp(event_hash, event["zkp"]):
                                    valid_events.append(event)
                                else:
                                    logger.warning(f"ZKP verification failed for event_type={event['event_type']}")
                            else:
                                logger.warning(f"Signature verification failed for event_type={event['event_type']}")

                        # Log to QLDB
                        event_data = {
                            "query_hash": hashlib.sha3_512(statement.encode()).hexdigest(),
                            "event_count": len(valid_events),
                            "signature": sign_message(cbor2.dumps({"query_hash": hashlib.sha3_512(statement.encode()).hexdigest()}))
                        }
                        QLDBLogger.log_event("qldb_get_events", event_data)

                        # Cache for 60 seconds
                        self.redis_client.setex(cache_key, 60, json.dumps(valid_events))

                        # Publish to AWS IoT
                        payload = {
                            "query_hash": event_data["query_hash"],
                            "event_count": len(valid_events)
                        }
                        payload_bytes = cbor2.dumps(payload)
                        signature = sign_message(payload_bytes)
                        signed_payload = {'data': payload, 'signature': signature}

                        self.iot_client.publish(
                            topic=f"{IOT_TOPIC_PREFIX}/qldb/query",
                            qos=1,
                            payload=cbor2.dumps(signed_payload)
                        )

                        logger.info(f"Retrieved {len(valid_events)} recent events from QLDB")
                        return valid_events
                    except ClientError as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for get_recent_events: {e}")
                            time.sleep(2 ** attempt)
                        else:
                            logger.error(f"Failed to retrieve events after {retries} attempts: {e}")
                            return []
                    finally:
                        self._end_session()
            except Exception as e:
                logger.error(f"Failed to retrieve recent events: {e}")
                self._end_session()
                return []

# Example usage
if __name__ == "__main__":
    logger = QLDBLogger()
    success = logger.log_event(
        event_type="node_beacon",
        data={"node_id": "test123", "status": "green"},
        user="testuser"
    )
    print(f"Log event success: {success}")
    events = logger.get_recent_events(limit=10)
    print(f"Recent events: {len(events)} retrieved")