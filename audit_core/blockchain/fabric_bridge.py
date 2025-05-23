from hfc.fabric import Client as FabricClient
import json
import os
import logging
import threading
from dotenv import load_dotenv
import redis
import cbor2
import boto3
from botocore.exceptions import ClientError
from audit_core.audit_log.qldb_logger import QLDBLogger
from security_core.pqc.dilithium import DilithiumSigner
from security_core.zk_snark.zkp import generate_zkp, verify_zkp
import hashlib
import time
import orjson
from jsonschema import validate, ValidationError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/fabric_bridge.log')
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
NETWORK_PROFILE_PATH = os.getenv('FABRIC_NET_PROFILE', 'network.json')
CHANNEL_NAME = os.getenv('FABRIC_CHANNEL_NAME', 'audit-channel')
CHAINCODE_NAME = os.getenv('FABRIC_CHAINCODE_NAME', 'audit_cc')
ORG_NAME = os.getenv('FABRIC_ORG_NAME', 'org1.example.com')
USER_NAME = os.getenv('FABRIC_USER_NAME', 'Admin')
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')
IOT_TOPIC_PREFIX = os.getenv('IOT_TOPIC_PREFIX', 'mesh')

# JSON schema for audit events
EVENT_SCHEMA = {
    "type": "object",
    "properties": {
        "event_id": {"type": "string"},
        "type": {"type": "string"},
        "timestamp": {"type": "string"},
        "data": {"type": "object"},
        "signature": {"type": "string"},
        "public_key": {"type": "string"},
        "zkp": {"type": "string"}
    },
    "required": ["event_id", "type", "timestamp"]
}

class FabricBridge:
    """
    Handles submission of audit events to Hyperledger Fabric for immutable storage.
    Integrates with QLDB, IoT, and PQC for secure blockchain operations.
    """

    def __init__(self, network_profile_path=NETWORK_PROFILE_PATH, channel_name=CHANNEL_NAME, chaincode_name=CHAINCODE_NAME):
        self.client = FabricClient(net_profile=network_profile_path)
        self.channel_name = channel_name
        self.chaincode_name = chaincode_name
        self.org = ORG_NAME
        self.user = USER_NAME
        self.lock = threading.Lock()
        self.redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
        self.iot_client = boto3.client('iot-data', region_name=AWS_REGION)
        self.signer = DilithiumSigner()
        self.logger = QLDBLogger()
        self._init_channel()

    def _init_channel(self):
        """Initialize Fabric channel."""
        with self.lock:
            try:
                self.client.new_channel(self.channel_name)
                logger.info(f"Initialized Fabric channel: {self.channel_name}")
            except Exception as e:
                logger.error(f"Failed to initialize Fabric channel: {e}")
                raise

    def submit_audit_event(self, event, retries=3):
        """
        Submits an audit event to the blockchain as a transaction with PQC signatures.
        """
        with self.lock:
            if not isinstance(event, dict):
                logger.warning(f"Invalid event: {event}")
                raise ValueError("Event must be a dictionary")

            try:
                # Validate event
                validate(instance=event, schema=EVENT_SCHEMA)

                # Generate Dilithium signature
                event_bytes = cbor2.dumps(event)
                pub_key, priv_key = self.signer.keygen()
                signature = self.signer.sign(event_bytes, priv_key)
                event["signature"] = signature
                event["public_key"] = pub_key

                # Generate ZKP for event integrity
                event_hash = hashlib.sha3_512(event_bytes).hexdigest()
                zkp = generate_zkp(event_hash)
                if not verify_zkp(event_hash, zkp):
                    logger.warning(f"ZKP verification failed for event_hash={event_hash[:16]}...")
                    raise RuntimeError("Event integrity verification failed")
                event["zkp"] = zkp

                cache_key = f"fabric_event_{event_hash}"
                cached_response = self.redis_client.get(cache_key)
                if cached_response:
                    logger.debug(f"Returning cached transaction response: event_hash={event_hash[:16]}...")
                    return json.loads(cached_response)

                for attempt in range(retries):
                    try:
                        response = self.client.chaincode_invoke(
                            requestor=self.user,
                            channel_name=self.channel_name,
                            peer_names=[f'peer0.{self.org}'],
                            args=[orjson.dumps(event, option=orjson.OPT_SORT_KEYS).decode()],
                            cc_name=self.chaincode_name,
                            fcn='addAuditEvent',
                            wait_for_event=True
                        )

                        # Log to QLDB
                        qldb_event_data = {
                            "event_hash": event_hash,
                            "event_id": event.get("event_id", "unknown"),
                            "transaction_id": str(response),
                            "signature": self.signer.sign(
                                cbor2.dumps({"event_hash": event_hash}),
                                priv_key
                            )
                        }
                        self.logger.log_event("fabric_submit_event", qldb_event_data)

                        # Cache response for 300 seconds
                        self.redis_client.setex(cache_key, 300, json.dumps(str(response)))

                        # Publish to AWS IoT
                        payload = {
                            "event_hash": event_hash,
                            "event_id": event.get("event_id", "unknown"),
                            "transaction_id": str(response),
                            "public_key": pub_key[:16]
                        }
                        payload_bytes = cbor2.dumps(payload)
                        signature = self.signer.sign(payload_bytes, priv_key)
                        signed_payload = {'data': payload, 'signature': signature}

                        try:
                            self.iot_client.publish(
                                topic=f"{IOT_TOPIC_PREFIX}/fabric/submit",
                                qos=1,
                                payload=cbor2.dumps(signed_payload)
                            )
                        except ClientError as e:
                            logger.warning(f"IoT publish error: {e}")

                        logger.info(f"Submitted audit event to Fabric: event_id={event.get('event_id', 'unknown')}, transaction_id={response}")
                        return str(response)
                    except Exception as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for submit_audit_event: {e}")
                            time.sleep(2 ** attempt)
                        else:
                            logger.error(f"Failed to submit audit event after {retries} attempts: {e}")
                            return None
            except ValidationError as e:
                logger.error(f"Invalid event schema: {e}")
                raise
            except Exception as e:
                logger.error(f"Fabric submission failed: {e}")
                return None

    def batch_submit_audit_events(self, events, retries=3):
        """
        Submits multiple audit events to the blockchain in a single transaction.
        """
        with self.lock:
            if not isinstance(events, list) or not all(isinstance(event, dict) for event in events):
                logger.warning(f"Invalid events: {events}")
                raise ValueError("Events must be a list of dictionaries")

            try:
                # Validate events
                for event in events:
                    validate(instance=event, schema=EVENT_SCHEMA)

                # Generate signatures and ZKPs for each event
                signed_events = []
                event_hashes = []
                for event in events:
                    event_bytes = cbor2.dumps(event)
                    pub_key, priv_key = self.signer.keygen()
                    signature = self.signer.sign(event_bytes, priv_key)
                    event["signature"] = signature
                    event["public_key"] = pub_key

                    event_hash = hashlib.sha3_512(event_bytes).hexdigest()
                    zkp = generate_zkp(event_hash)
                    if not verify_zkp(event_hash, zkp):
                        logger.warning(f"ZKP verification failed for event_id={event.get('event_id', 'unknown')}")
                        raise RuntimeError("Event integrity verification failed")
                    event["zkp"] = zkp
                    signed_events.append(event)
                    event_hashes.append(event_hash)

                batch_hash = hashlib.sha3_512(cbor2.dumps(event_hashes)).hexdigest()
                cache_key = f"fabric_batch_{batch_hash}"
                cached_response = self.redis_client.get(cache_key)
                if cached_response:
                    logger.debug(f"Returning cached batch transaction response: batch_hash={batch_hash[:16]}...")
                    return json.loads(cached_response)

                for attempt in range(retries):
                    try:
                        response = self.client.chaincode_invoke(
                            requestor=self.user,
                            channel_name=self.channel_name,
                            peer_names=[f'peer0.{self.org}'],
                            args=[orjson.dumps(signed_events, option=orjson.OPT_SORT_KEYS).decode()],
                            cc_name=self.chaincode_name,
                            fcn='addAuditEventsBatch',
                            wait_for_event=True
                        )

                        # Log to QLDB
                        qldb_event_data = {
                            "batch_hash": batch_hash,
                            "event_count": len(events),
                            "transaction_id": str(response),
                            "signature": self.signer.sign(
                                cbor2.dumps({"batch_hash": batch_hash}),
                                self.signer.keygen()[1]
                            )
                        }
                        self.logger.log_event("fabric_batch_submit", qldb_event_data)

                        # Cache response for 300 seconds
                        self.redis_client.setex(cache_key, 300, json.dumps(str(response)))

                        # Publish to AWS IoT
                        payload = {
                            "batch_hash": batch_hash,
                            "event_count": len(events),
                            "transaction_id": str(response)
                        }
                        payload_bytes = cbor2.dumps(payload)
                        signature = self.signer.sign(payload_bytes, self.signer.keygen()[1])
                        signed_payload = {'data': payload, 'signature': signature}

                        try:
                            self.iot_client.publish(
                                topic=f"{IOT_TOPIC_PREFIX}/fabric/batch_submit",
                                qos=1,
                                payload=cbor2.dumps(signed_payload)
                            )
                        except ClientError as e:
                            logger.warning(f"IoT publish error: {e}")

                        logger.info(f"Submitted {len(events)} audit events to Fabric: batch_hash={batch_hash[:16]}..., transaction_id={response}")
                        return str(response)
                    except Exception as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for batch_submit_audit_events: {e}")
                            time.sleep(2 ** attempt)
                        else:
                            logger.error(f"Failed to submit batch audit events after {retries} attempts: {e}")
                            return None
            except ValidationError as e:
                logger.error(f"Invalid event schema in batch: {e}")
                raise
            except Exception as e:
                logger.error(f"Fabric batch submission failed: {e}")
                return None

    def fetch_event(self, event_id, retries=3):
        """
        Fetch a single event from the blockchain.
        """
        with self.lock:
            if not isinstance(event_id, str) or not event_id.strip():
                logger.warning(f"Invalid event_id: {event_id}")
                raise ValueError("Invalid event_id")

            try:
                cache_key = f"fabric_fetch_{event_id}"
                cached_event = self.redis_client.get(cache_key)
                if cached_event:
                    logger.debug(f"Returning cached event: event_id={event_id}")
                    return json.loads(cached_event)

                for attempt in range(retries):
                    try:
                        response = self.client.chaincode_query(
                            requestor=self.user,
                            channel_name=self.channel_name,
                            peer_names=[f'peer0.{self.org}'],
                            args=[event_id],
                            cc_name=self.chaincode_name,
                            fcn='getAuditEvent'
                        )
                        event = orjson.loads(response)

                        # Verify signature and ZKP
                        event_data = {k: v for k, v in event.items() if k not in ["signature", "public_key", "zkp"]}
                        event_bytes = cbor2.dumps(event_data)
                        event_hash = hashlib.sha3_512(event_bytes).hexdigest()
                        if not self.signer.verify(event_bytes, event["signature"], event["public_key"]):
                            logger.warning(f"Signature verification failed for event_id={event_id}")
                            return None
                        if not verify_zkp(event_hash, event["zkp"]):
                            logger.warning(f"ZKP verification failed for event_id={event_id}")
                            return None

                        # Log to QLDB
                        qldb_event_data = {
                            "event_id": event_id,
                            "event_hash": event_hash,
                            "signature": self.signer.sign(
                                cbor2.dumps({"event_id": event_id}),
                                self.signer.keygen()[1]
                            )
                        }
                        self.logger.log_event("fabric_fetch_event", qldb_event_data)

                        # Cache event for 300 seconds
                        self.redis_client.setex(cache_key, 300, json.dumps(event))

                        # Publish to AWS IoT
                        payload = {
                            "event_id": event_id,
                            "event_hash": event_hash
                        }
                        payload_bytes = cbor2.dumps(payload)
                        signature = self.signer.sign(payload_bytes, self.signer.keygen()[1])
                        signed_payload = {'data': payload, 'signature': signature}

                        try:
                            self.iot_client.publish(
                                topic=f"{IOT_TOPIC_PREFIX}/fabric/fetch",
                                qos=1,
                                payload=cbor2.dumps(signed_payload)
                            )
                        except ClientError as e:
                            logger.warning(f"IoT publish error: {e}")

                        logger.info(f"Fetched event from Fabric: event_id={event_id}")
                        return event
                    except Exception as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for fetch_event: {e}")
                            time.sleep(2 ** attempt)
                        else:
                            logger.error(f"Failed to fetch event after {retries} attempts: {e}")
                            return None
            except Exception as e:
                logger.error(f"Fabric fetch failed: {e}")
                return None

    def fetch_all_events(self, limit=100, offset=0, retries=3):
        """
        Fetch all audit events from the blockchain with pagination.
        """
        with self.lock:
            try:
                cache_key = f"fabric_fetch_all_{limit}_{offset}"
                cached_events = self.redis_client.get(cache_key)
                if cached_events:
                    logger.debug(f"Returning cached all events: limit={limit}, offset={offset}")
                    return json.loads(cached_events)

                for attempt in range(retries):
                    try:
                        response = self.client.chaincode_query(
                            requestor=self.user,
                            channel_name=self.channel_name,
                            peer_names=[f'peer0.{self.org}'],
                            args=[str(limit), str(offset)],
                            cc_name=self.chaincode_name,
                            fcn='getAllAuditEvents'
                        )
                        events = orjson.loads(response)

                        # Verify signatures and ZKPs
                        valid_events = []
                        for event in events:
                            event_data = {k: v for k, v in event.items() if k not in ["signature", "public_key", "zkp"]}
                            event_bytes = cbor2.dumps(event_data)
                            event_hash = hashlib.sha3_512(event_bytes).hexdigest()
                            if self.signer.verify(event_bytes, event["signature"], event["public_key"]) and verify_zkp(event_hash, event["zkp"]):
                                valid_events.append(event)
                            else:
                                logger.warning(f"Verification failed for event_id={event.get('event_id', 'unknown')}")

                        # Log to QLDB
                        qldb_event_data = {
                            "event_count": len(valid_events),
                            "limit": limit,
                            "offset": offset,
                            "signature": self.signer.sign(
                                cbor2.dumps({"event_count": len(valid_events)}),
                                self.signer.keygen()[1]
                            )
                        }
                        self.logger.log_event("fabric_fetch_all", qldb_event_data)

                        # Cache events for 300 seconds
                        self.redis_client.setex(cache_key, 300, json.dumps(valid_events))

                        # Publish to AWS IoT
                        payload = {
                            "event_count": len(valid_events),
                            "limit": limit,
                            "offset": offset
                        }
                        payload_bytes = cbor2.dumps(payload)
                        signature = self.signer.sign(payload_bytes, self.signer.keygen()[1])
                        signed_payload = {'data': payload, 'signature': signature}

                        try:
                            self.iot_client.publish(
                                topic=f"{IOT_TOPIC_PREFIX}/fabric/fetch_all",
                                qos=1,
                                payload=cbor2.dumps(signed_payload)
                            )
                        except ClientError as e:
                            logger.warning(f"IoT publish error: {e}")

                        logger.info(f"Fetched {len(valid_events)} events from Fabric: limit={limit}, offset={offset}")
                        return valid_events
                    except Exception as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for fetch_all_events: {e}")
                            time.sleep(2 ** attempt)
                        else:
                            logger.error(f"Failed to fetch all events after {retries} attempts: {e}")
                            return []
            except Exception as e:
                logger.error(f"Fabric fetch all failed: {e}")
                return []

# Example usage
if __name__ == "__main__":
    bridge = FabricBridge()
    test_event = {"event_id": "12345", "type": "login", "timestamp": "2035-06-01T12:00:00Z"}
    print("Submitting:", bridge.submit_audit_event(test_event))
    print("Fetched:", bridge.fetch_event("12345"))
    print("All events:", bridge.fetch_all_events(limit=10, offset=0))