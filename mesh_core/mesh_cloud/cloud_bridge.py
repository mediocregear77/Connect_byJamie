import boto3
import json
import logging
import threading
from dotenv import load_dotenv
import os
import cbor2
import redis
from botocore.exceptions import ClientError
from paho.mqtt import client as mqtt_client
from audit_core.audit_log.qldb_logger import QLDBLogger
from security_core.pqc.dilithium import sign_message
import time
import random

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/cloud_bridge.log')
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')
IOT_TOPIC_PREFIX = os.getenv('IOT_TOPIC_PREFIX', 'mesh')
MQTT_BROKER = os.getenv('MQTT_BROKER', 'localhost')
MQTT_PORT = int(os.getenv('MQTT_PORT', 1883))
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')

class CloudBridge:
    def __init__(self, mesh_node_id, region_name=AWS_REGION):
        self.mesh_node_id = mesh_node_id
        self.region_name = region_name
        self.iot_client = boto3.client('iot-data', region_name=region_name)
        self.topic_prefix = f"{IOT_TOPIC_PREFIX}/{self.mesh_node_id}/"
        self.lock = threading.Lock()
        self.redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
        self.mqtt_client = mqtt_client.Client(client_id=f"bridge_{mesh_node_id}_{random.randint(0, 1000)}")
        self.mqtt_client.on_message = self._on_message
        self.mqtt_client.on_connect = self._on_connect
        self.mqtt_callbacks = {}

    def _on_connect(self, client, userdata, flags, rc):
        """Handle MQTT connection."""
        if rc == 0:
            logger.info(f"MQTT connected for node_id={self.mesh_node_id}")
            # Subscribe to all topics under prefix
            client.subscribe(f"{self.topic_prefix}#")
        else:
            logger.error(f"MQTT connection failed for node_id={self.mesh_node_id}, code={rc}")

    def _on_message(self, client, userdata, msg):
        """Handle incoming MQTT messages."""
        try:
            topic = msg.topic
            payload = cbor2.loads(msg.payload)
            callback = self.mqtt_callbacks.get(topic)
            if callback:
                callback(topic, payload)
                logger.info(f"Processed message on topic={topic} for node_id={self.mesh_node_id}")
            else:
                logger.debug(f"No callback for topic={topic}")
        except Exception as e:
            logger.error(f"Failed to process MQTT message on topic={topic}: {e}")

    def send_message(self, topic, payload, retries=3):
        """Send message to AWS IoT with PQC signing and retry logic."""
        with self.lock:
            topic_full = self.topic_prefix + topic
            try:
                # Serialize and sign payload
                payload_bytes = cbor2.dumps(payload)
                signature = sign_message(payload_bytes)
                signed_payload = {'data': payload, 'signature': signature}

                # Publish with retries
                for attempt in range(retries):
                    try:
                        response = self.iot_client.publish(
                            topic=topic_full,
                            qos=1,
                            payload=cbor2.dumps(signed_payload)
                        )
                        # Log to QLDB
                        event_data = {
                            "node_id": self.mesh_node_id,
                            "topic": topic_full,
                            "payload_hash": hashlib.sha3_512(payload_bytes).hexdigest(),
                            "signature": signature
                        }
                        QLDBLogger.log_event("cloud_bridge_publish", event_data)
                        logger.info(f"Published message to {topic_full}")
                        return response
                    except ClientError as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for {topic_full}: {e}")
                            time.sleep(2 ** attempt)  # Exponential backoff
                        else:
                            logger.error(f"Failed to publish to {topic_full} after {retries} attempts: {e}")
                            return None
            except Exception as e:
                logger.error(f"Error publishing to {topic_full}: {e}")
                return None

    def receive_message(self, topic, callback):
        """Subscribe to MQTT topic for message reception."""
        with self.lock:
            try:
                topic_full = self.topic_prefix + topic
                self.mqtt_callbacks[topic_full] = callback
                
                # Connect to MQTT broker if not already connected
                if not self.mqtt_client.is_connected():
                    self.mqtt_client.connect(MQTT_BROKER, MQTT_PORT)
                    self.mqtt_client.loop_start()
                
                logger.info(f"Subscribed to {topic_full} for node_id={self.mesh_node_id}")
                return True
            except Exception as e:
                logger.error(f"Failed to subscribe to {topic_full}: {e}")
                return False

    def sync_node_state(self, state):
        """Sync node state to cloud with caching and QLDB logging."""
        cache_key = f"node_state_{self.mesh_node_id}"
        try:
            # Check cache
            cached_state = self.redis_client.get(cache_key)
            if cached_state and json.loads(cached_state) == state:
                logger.debug(f"Skipping state sync, no changes for node_id={self.mesh_node_id}")
                return True

            # Publish state
            response = self.send_message("state", state)
            if response:
                # Cache state for 60 seconds
                self.redis_client.setex(cache_key, 60, json.dumps(state))
                logger.info(f"Synced node state for node_id={self.mesh_node_id}")
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to sync node state for node_id={self.mesh_node_id}: {e}")
            return False

    def shutdown(self):
        """Cleanly shutdown MQTT client."""
        with self.lock:
            try:
                if self.mqtt_client.is_connected():
                    self.mqtt_client.loop_stop()
                    self.mqtt_client.disconnect()
                    logger.info(f"Shutdown MQTT client for node_id={self.mesh_node_id}")
            except Exception as e:
                logger.error(f"Failed to shutdown MQTT client: {e}")

# Example usage
if __name__ == "__main__":
    bridge = CloudBridge(mesh_node_id="node-001")
    bridge.sync_node_state({"status": "online", "uptime": 123456})
    # Example subscription
    def state_callback(topic, payload):
        print(f"Received on {topic}: {payload}")
    bridge.receive_message("state", state_callback)
    time.sleep(5)  # Keep running to process messages
    bridge.shutdown()