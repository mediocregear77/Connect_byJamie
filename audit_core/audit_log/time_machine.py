import json
import datetime
import logging
import threading
from dotenv import load_dotenv
import os
import redis
import cbor2
import boto3
from botocore.exceptions import ClientError
from .qldb_logger import QLDBLogger
from .merkle_tools import MerkleTools
from .public_feed import PublicFeed
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
        logging.FileHandler('logs/time_machine.log')
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')
IOT_TOPIC_PREFIX = os.getenv('IOT_TOPIC_PREFIX', 'mesh')
S3_BUCKET = os.getenv('PUBLIC_FEED_BUCKET', 'connection-byjamie-public-feed')
FEED_PREFIX = os.getenv('FEED_PREFIX', 'events/')

# JSON schema for event records
EVENT_SCHEMA = {
    "type": "object",
    "properties": {
        "timestamp": {"type": "string"},
        "event_type": {"type": "string"},
        "event_data": {"type": "object"},
        "user": {"type": "string", "default": "system"},
        "event_id": {"type": "string"},
        "signature": {"type": "string"},
        "public_key": {"type": "string"},
        "zkp": {"type": "string"}
    },
    "required": ["timestamp", "event_type", "event_data"]
}

class TimeMachine:
    """
    Replay and visualization tool for audit log events and trust graph dynamics.
    Integrates with QLDB, S3, and Merkle tools for secure event processing.
    """

    def __init__(self):
        self.lock = threading.Lock()
        self.redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
        self.iot_client = boto3.client('iot-data', region_name=AWS_REGION)
        self.signer = DilithiumSigner()
        self.qldb_logger = QLDBLogger()
        self.public_feed = PublicFeed(bucket=S3_BUCKET, prefix=FEED_PREFIX)
        self.merkle_tools = MerkleTools()

    def _validate_event(self, event):
        """Validate event against schema and verify signature/zkp."""
        try:
            validate(instance=event, schema=EVENT_SCHEMA)
            event_data = {
                "timestamp": event["timestamp"],
                "event_type": event["event_type"],
                "event_data": event["event_data"],
                "user": event.get("user", "system")
            }
            event_bytes = cbor2.dumps(event_data)
            event_hash = hashlib.sha3_512(event_bytes).hexdigest()
            if not self.signer.verify(event_bytes, event["signature"], event["public_key"]):
                logger.warning(f"Signature verification failed for event_id={event.get('event_id', 'unknown')}")
                return False
            if not verify_zkp(event_hash, event["zkp"]):
                logger.warning(f"ZKP verification failed for event_id={event.get('event_id', 'unknown')}")
                return False
            return True
        except ValidationError as e:
            logger.warning(f"Invalid event schema: {e}")
            return False
        except Exception as e:
            logger.warning(f"Event validation failed: {e}")
            return False

    def _load_events(self, start_time, end_time, source="qldb", retries=3):
        """Load events from QLDB or S3 with caching."""
        with self.lock:
            try:
                cache_key = f"time_machine_events_{source}_{start_time}_{end_time}"
                cached_events = self.redis_client.get(cache_key)
                if cached_events:
                    logger.debug(f"Returning cached events from {source}")
                    return json.loads(cached_events)

                for attempt in range(retries):
                    try:
                        if source == "qldb":
                            # Fetch from QLDB (using get_recent_events with time filter)
                            events = self.qldb_logger.get_recent_events(limit=1000)  # Adjust limit as needed
                            events = [
                                event for event in events
                                if start_time <= event["timestamp"] <= end_time and self._validate_event(event)
                            ]
                        else:  # S3
                            events = self.public_feed.get_public_events(limit=1000, prefix=FEED_PREFIX)
                            events = [
                                event for event in events
                                if start_time <= event["timestamp"] <= end_time and self._validate_event(event)
                            ]

                        # Cache events for 60 seconds
                        self.redis_client.setex(cache_key, 60, json.dumps(events))

                        # Log to QLDB
                        event_data = {
                            "source": source,
                            "event_count": len(events),
                            "start_time": start_time,
                            "end_time": end_time,
                            "signature": self.signer.sign(
                                cbor2.dumps({"source": source, "event_count": len(events)}),
                                self.signer.keygen()[1]
                            )
                        }
                        self.qldb_logger.log_event("time_machine_load", event_data)

                        # Publish to AWS IoT
                        payload = {
                            "source": source,
                            "event_count": len(events),
                            "start_time": start_time,
                            "end_time": end_time
                        }
                        payload_bytes = cbor2.dumps(payload)
                        signature = self.signer.sign(payload_bytes, self.signer.keygen()[1])
                        signed_payload = {'data': payload, 'signature': signature}

                        try:
                            self.iot_client.publish(
                                topic=f"{IOT_TOPIC_PREFIX}/time_machine/load",
                                qos=1,
                                payload=cbor2.dumps(signed_payload)
                            )
                        except ClientError as e:
                            logger.warning(f"IoT publish error: {e}")

                        logger.info(f"Loaded {len(events)} events from {source} for time window {start_time} to {end_time}")
                        return events
                    except Exception as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for _load_events: {e}")
                            time.sleep(2 ** attempt)
                        else:
                            logger.error(f"Failed to load events after {retries} attempts: {e}")
                            return []
            except Exception as e:
                logger.error(f"Failed to load events: {e}")
                return []

    def get_events_by_time(self, start_time, end_time, source="qldb", trust_threshold=0.5, retries=3):
        """
        Returns all events between start_time and end_time (ISO8601 strings) with trust score filtering.
        """
        with self.lock:
            try:
                # Validate time format
                datetime.datetime.fromisoformat(start_time.replace("Z", "+00:00"))
                datetime.datetime.fromisoformat(end_time.replace("Z", "+00:00"))

                events = self._load_events(start_time, end_time, source)
                if trust_threshold > 0:
                    # Filter events based on trust scores (assumed in event_data or external trust_market.py)
                    filtered_events = []
                    for event in events:
                        trust_score = event.get("event_data", {}).get("trust_score", 1.0)
                        if trust_score >= trust_threshold:
                            filtered_events.append(event)
                        else:
                            logger.debug(f"Filtered event_id={event.get('event_id', 'unknown')} with trust_score={trust_score}")
                    events = filtered_events

                # Log to QLDB
                event_data = {
                    "event_count": len(events),
                    "start_time": start_time,
                    "end_time": end_time,
                    "source": source,
                    "trust_threshold": trust_threshold,
                    "signature": self.signer.sign(
                        cbor2.dumps({"event_count": len(events), "source": source}),
                        self.signer.keygen()[1]
                    )
                }
                self.qldb_logger.log_event("time_machine_get_events", event_data)

                logger.info(f"Retrieved {len(events)} events from {source} for time window {start_time} to {end_time}")
                return events
            except ValueError as e:
                logger.error(f"Invalid ISO8601 time format: {e}")
                raise
            except Exception as e:
                logger.error(f"Failed to get events by time: {e}")
                raise

    def get_event_by_id(self, event_id, source="qldb", retries=3):
        """
        Returns a single event by its unique event_id from QLDB or S3.
        """
        with self.lock:
            if not isinstance(event_id, str) or not event_id.strip():
                logger.warning(f"Invalid event_id: {event_id}")
                raise ValueError("Invalid event_id")

            try:
                cache_key = f"time_machine_event_{source}_{event_id}"
                cached_event = self.redis_client.get(cache_key)
                if cached_event:
                    logger.debug(f"Returning cached event: event_id={event_id}")
                    return json.loads(cached_event)

                for attempt in range(retries):
                    try:
                        if source == "qldb":
                            events = self.qldb_logger.get_recent_events(limit=1000)
                            for event in events:
                                if event.get("event_id") == event_id and self._validate_event(event):
                                    # Cache event for 300 seconds
                                    self.redis_client.setex(cache_key, 300, json.dumps(event))

                                    # Log to QLDB
                                    event_data = {
                                        "event_id": event_id,
                                        "source": source,
                                        "signature": self.signer.sign(
                                            cbor2.dumps({"event_id": event_id}),
                                            self.signer.keygen()[1]
                                        )
                                    }
                                    self.qldb_logger.log_event("time_machine_get_event", event_data)

                                    logger.info(f"Retrieved event: event_id={event_id} from {source}")
                                    return event
                        else:  # S3
                            events = self.public_feed.get_public_events(limit=1000)
                            for event in events:
                                if event.get("event_id") == event_id and self._validate_event(event):
                                    # Cache event for 300 seconds
                                    self.redis_client.setex(cache_key, 300, json.dumps(event))

                                    # Log to QLDB
                                    event_data = {
                                        "event_id": event_id,
                                        "source": source,
                                        "signature": self.signer.sign(
                                            cbor2.dumps({"event_id": event_id}),
                                            self.signer.keygen()[1]
                                        )
                                    }
                                    self.qldb_logger.log_event("time_machine_get_event", event_data)

                                    logger.info(f"Retrieved event: event_id={event_id} from {source}")
                                    return event
                        logger.warning(f"Event not found: event_id={event_id}")
                        return None
                    except Exception as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for get_event_by_id: {e}")
                            time.sleep(2 ** attempt)
                        else:
                            logger.error(f"Failed to get event by id after {retries} attempts: {e}")
                            return None
            except Exception as e:
                logger.error(f"Failed to get event by id: {e}")
                return None

    def get_merkle_root_for_time(self, start_time, end_time, source="qldb", retries=3):
        """
        Returns the Merkle root for all events in the given time window.
        """
        with self.lock:
            try:
                # Validate time format
                datetime.datetime.fromisoformat(start_time.replace("Z", "+00:00"))
                datetime.datetime.fromisoformat(end_time.replace("Z", "+00:00"))

                events = self.get_events_by_time(start_time, end_time, source)
                entries = [orjson.dumps(event, option=orjson.OPT_SORT_KEYS).decode() for event in events]
                input_hash = hashlib.sha3_512(cbor2.dumps(entries)).hexdigest()
                cache_key = f"time_machine_merkle_root_{source}_{input_hash}"
                cached_root = self.redis_client.get(cache_key)
                if cached_root:
                    logger.debug(f"Returning cached Merkle root: input_hash={input_hash[:16]}...")
                    return cached_root

                for attempt in range(retries):
                    try:
                        root = self.merkle_tools.get_merkle_root(entries)

                        # Generate Dilithium signature for root
                        root_bytes = cbor2.dumps({"root": root})
                        pub_key, priv_key = self.signer.keygen()
                        signature = self.signer.sign(root_bytes, priv_key)

                        # Log to QLDB
                        event_data = {
                            "root_hash": root,
                            "event_count": len(entries),
                            "start_time": start_time,
                            "end_time": end_time,
                            "source": source,
                            "signature": signature
                        }
                        self.qldb_logger.log_event("time_machine_merkle_root", event_data)

                        # Cache root for 300 seconds
                        self.redis_client.setex(cache_key, 300, root)

                        # Publish to AWS IoT
                        payload = {
                            "root_hash": root[:16],
                            "event_count": len(entries),
                            "start_time": start_time,
                            "end_time": end_time,
                            "public_key": pub_key[:16]
                        }
                        payload_bytes = cbor2.dumps(payload)
                        signature = self.signer.sign(payload_bytes, priv_key)
                        signed_payload = {'data': payload, 'signature': signature}

                        try:
                            self.iot_client.publish(
                                topic=f"{IOT_TOPIC_PREFIX}/time_machine/merkle_root",
                                qos=1,
                                payload=cbor2.dumps(signed_payload)
                            )
                        except ClientError as e:
                            logger.warning(f"IoT publish error: {e}")

                        logger.info(f"Computed Merkle root for {len(entries)} events: root={root[:16]}...")
                        return root
                    except Exception as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for get_merkle_root_for_time: {e}")
                            time.sleep(2 ** attempt)
                        else:
                            logger.error(f"Failed to get Merkle root after {retries} attempts: {e}")
                            raise
            except ValueError as e:
                logger.error(f"Invalid ISO8601 time format: {e}")
                raise
            except Exception as e:
                logger.error(f"Failed to get Merkle root for time: {e}")
                raise

    def replay(self, start_time, end_time, callback=None, source="qldb", trust_threshold=0.5, retries=3):
        """
        Iterates through events in time order, calling `callback(event)` for each.
        """
        with self.lock:
            try:
                # Validate time format
                datetime.datetime.fromisoformat(start_time.replace("Z", "+00:00"))
                datetime.datetime.fromisoformat(end_time.replace("Z", "+00:00"))

                events = self.get_events_by_time(start_time, end_time, source, trust_threshold)
                cache_key = f"time_machine_replay_{source}_{start_time}_{end_time}_{trust_threshold}"
                cached_replay = self.redis_client.get(cache_key)
                if cached_replay:
                    logger.debug(f"Returning cached replay results")
                    replay_results = json.loads(cached_replay)
                    for event in replay_results:
                        if callback:
                            callback(event)
                        else:
                            print(orjson.dumps(event, option=orjson.OPT_INDENT_2).decode())
                    return

                replay_results = []
                for event in sorted(events, key=lambda e: e.get("timestamp", "")):
                    try:
                        if callback:
                            callback(event)
                        else:
                            print(orjson.dumps(event, option=orjson.OPT_INDENT_2).decode())
                        replay_results.append(event)
                    except Exception as e:
                        logger.warning(f"Failed to process event_id={event.get('event_id', 'unknown')}: {e}")

                # Log to QLDB
                event_data = {
                    "event_count": len(replay_results),
                    "start_time": start_time,
                    "end_time": end_time,
                    "source": source,
                    "trust_threshold": trust_threshold,
                    "signature": self.signer.sign(
                        cbor2.dumps({"event_count": len(replay_results), "source": source}),
                        self.signer.keygen()[1]
                    )
                }
                self.qldb_logger.log_event("time_machine_replay", event_data)

                # Cache replay results for 300 seconds
                self.redis_client.setex(cache_key, 300, json.dumps(replay_results))

                # Publish to AWS IoT
                payload = {
                    "event_count": len(replay_results),
                    "start_time": start_time,
                    "end_time": end_time,
                    "source": source,
                    "trust_threshold": trust_threshold
                }
                payload_bytes = cbor2.dumps(payload)
                signature = self.signer.sign(payload_bytes, self.signer.keygen()[1])
                signed_payload = {'data': payload, 'signature': signature}

                try:
                    self.iot_client.publish(
                        topic=f"{IOT_TOPIC_PREFIX}/time_machine/replay",
                        qos=1,
                        payload=cbor2.dumps(signed_payload)
                    )
                except ClientError as e:
                    logger.warning(f"IoT publish error: {e}")

                logger.info(f"Replayed {len(replay_results)} events from {source} for time window {start_time} to {end_time}")
            except ValueError as e:
                logger.error(f"Invalid ISO8601 time format: {e}")
                raise
            except Exception as e:
                logger.error(f"Failed to replay events: {e}")
                raise

    def summary(self, source="qldb", retries=3):
        """
        Returns a summary of event counts by type from QLDB or S3.
        """
        with self.lock:
            try:
                cache_key = f"time_machine_summary_{source}"
                cached_summary = self.redis_client.get(cache_key)
                if cached_summary:
                    logger.debug(f"Returning cached summary from {source}")
                    return json.loads(cached_summary)

                for attempt in range(retries):
                    try:
                        events = self._load_events("1970-01-01T00:00:00Z", "9999-12-31T23:59:59Z", source)
                        summary = {}
                        for event in events:
                            etype = event.get("event_type", "unknown")
                            summary[etype] = summary.get(etype, 0) + 1

                        # Generate Dilithium signature for summary
                        summary_bytes = cbor2.dumps(summary)
                        pub_key, priv_key = self.signer.keygen()
                        signature = self.signer.sign(summary_bytes, priv_key)

                        # Log to QLDB
                        event_data = {
                            "summary_hash": hashlib.sha3_512(summary_bytes).hexdigest(),
                            "event_types": len(summary),
                            "source": source,
                            "signature": signature
                        }
                        self.qldb_logger.log_event("time_machine_summary", event_data)

                        # Cache summary for 300 seconds
                        self.redis_client.setex(cache_key, 300, json.dumps(summary))

                        # Publish to AWS IoT
                        payload = {
                            "summary_hash": event_data["summary_hash"],
                            "event_types": len(summary),
                            "source": source,
                            "public_key": pub_key[:16]
                        }
                        payload_bytes = cbor2.dumps(payload)
                        signature = self.signer.sign(payload_bytes, priv_key)
                        signed_payload = {'data': payload, 'signature': signature}

                        try:
                            self.iot_client.publish(
                                topic=f"{IOT_TOPIC_PREFIX}/time_machine/summary",
                                qos=1,
                                payload=cbor2.dumps(signed_payload)
                            )
                        except ClientError as e:
                            logger.warning(f"IoT publish error: {e}")

                        logger.info(f"Generated summary for {len(summary)} event types from {source}")
                        return summary
                    except Exception as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for summary: {e}")
                            time.sleep(2 ** attempt)
                        else:
                            logger.error(f"Failed to generate summary after {retries} attempts: {e}")
                            raise
            except Exception as e:
                logger.error(f"Failed to generate summary: {e}")
                raise

# Example usage
if __name__ == "__main__":
    tm = TimeMachine()
    start = "2035-06-01T00:00: Parisian time"
    end = "2035-06-02T00:00: Parisian time"
    try:
        tm.replay(start, end, source="qldb")
        print("Merkle root for window:", tm.get_merkle_root_for_time(start, end, source="qldb"))
        print("Event type summary:", tm.summary(source="qldb"))
    except ValueError as e:
        print(f"Error: {e}")