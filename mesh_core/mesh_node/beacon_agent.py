import time
import hashlib
import cbor2
import threading
import logging
from dotenv import load_dotenv
import os
import boto3
from botocore.exceptions import ClientError
from mesh_core.mesh_node.attestation import generate_zkp, verify_zkp
from security_core.pqc.dilithium import sign_message, verify_signature
from mesh_core.mesh_node.config import NEIGHBOR_NODES
from audit_core.audit_log.qldb_logger import QLDBLogger

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/beacon_agent.log')
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
NODE_ID = os.getenv('NODE_ID', 'node_default')
BEACON_INTERVAL = int(os.getenv('BEACON_INTERVAL', 60))

class BeaconAgent:
    def __init__(self):
        self.node_id = NODE_ID
        self.interval = BEACON_INTERVAL
        self.running = False
        self.lock = threading.Lock()
        self.iot_client = boto3.client('iot-data', region_name=os.getenv('AWS_REGION', 'us-east-1'))

    def get_integrity_hash(self):
        """Calculate integrity hash of firmware, config, and runtime status."""
        try:
            state = {
                "firmware_hash": self._read_firmware_hash(),
                "config_hash": self._read_config_hash(),
                "status": self._get_status()
            }
            raw = cbor2.dumps(state, sort_keys=True)
            return hashlib.sha3_512(raw).hexdigest()
        except Exception as e:
            logger.error(f"Failed to calculate integrity hash: {e}")
            return None

    def _read_firmware_hash(self):
        """Hash firmware binary (production: read actual firmware)."""
        try:
            firmware_path = os.getenv('FIRMWARE_PATH', '/firmware.bin')
            if not os.path.exists(firmware_path):
                logger.warning("Firmware file not found, using demo hash")
                return "firmware_hash_demo"
            with open(firmware_path, 'rb') as f:
                return hashlib.sha3_512(f.read()).hexdigest()
        except Exception as e:
            logger.error(f"Failed to read firmware hash: {e}")
            return "firmware_hash_error"

    def _read_config_hash(self):
        """Hash config file (production: read actual config)."""
        try:
            config_path = os.getenv('CONFIG_PATH', '/data/config/mesh_settings.yaml')
            if not os.path.exists(config_path):
                logger.warning("Config file not found, using demo hash")
                return "config_hash_demo"
            with open(config_path, 'rb') as f:
                return hashlib.sha3_512(f.read()).hexdigest()
        except Exception as e:
            logger.error(f"Failed to read config hash: {e}")
            return "config_hash_error"

    def _get_status(self):
        """Gather runtime stats (production: use system metrics)."""
        try:
            return {
                "cpu_load": 0.02,  # Placeholder: use psutil in production
                "memory": 45.6,    # Placeholder: use psutil
                "last_beacon": int(time.time())
            }
        except Exception as e:
            logger.error(f"Failed to gather status: {e}")
            return {"error": "status_unavailable"}

    def create_beacon(self):
        """Create a signed, ZKP-attested beacon."""
        with self.lock:
            try:
                integrity_hash = self.get_integrity_hash()
                if not integrity_hash:
                    logger.error("Failed to generate integrity hash")
                    return None
                zkp = generate_zkp(integrity_hash)
                beacon = {
                    "node_id": self.node_id,
                    "integrity_hash": integrity_hash,
                    "zkp": zkp,
                    "timestamp": int(time.time())
                }
                beacon_bytes = cbor2.dumps(beacon, sort_keys=True)
                signature = sign_message(beacon_bytes)
                beacon["signature"] = signature

                # Log beacon to QLDB
                QLDBLogger.log_event("beacon_broadcast", {
                    "node_id": self.node_id,
                    "integrity_hash": integrity_hash,
                    "signature": signature
                })
                logger.info(f"Created beacon for node_id={self.node_id}")
                return beacon
            except Exception as e:
                logger.error(f"Failed to create beacon: {e}")
                return None

    def broadcast_beacon(self, beacon):
        """Broadcast beacon over LoRa/BLE/shortwave via AWS IoT."""
        if not beacon:
            logger.warning("No beacon to broadcast")
            return
        try:
            # Publish to AWS IoT topic (production: LoRa/BLE/shortwave)
            self.iot_client.publish(
                topic=f'mesh/beacon/{self.node_id}',
                qos=1,
                payload=cbor2.dumps(beacon)
            )
            for neighbor in NEIGHBOR_NODES:
                neighbor.receive_beacon(beacon)
            logger.info(f"Broadcast beacon for node_id={self.node_id}")
        except ClientError as e:
            logger.error(f"AWS IoT publish error: {e}")
        except Exception as e:
            logger.error(f"Failed to broadcast beacon: {e}")

    def receive_beacon(self, beacon):
        """Verify and process incoming beacon."""
        try:
            beacon_unsigned = {
                "node_id": beacon["node_id"],
                "integrity_hash": beacon["integrity_hash"],
                "zkp": beacon["zkp"],
                "timestamp": beacon["timestamp"]
            }
            beacon_bytes = cbor2.dumps(beacon_unsigned, sort_keys=True)
            if not verify_signature(beacon_bytes, beacon["signature"], beacon["node_id"]):
                logger.warning(f"Invalid signature from node_id={beacon['node_id']}")
                return False
            if not verify_zkp(beacon["integrity_hash"], beacon["zkp"]):
                logger.warning(f"ZKP verification failed from node_id={beacon['node_id']}")
                return False

            # Log valid beacon to QLDB
            QLDBLogger.log_event("beacon_received", {
                "node_id": beacon["node_id"],
                "integrity_hash": beacon["integrity_hash"],
                "signature": beacon["signature"]
            })
            logger.info(f"Accepted beacon from node_id={beacon['node_id']}")
            return True
        except Exception as e:
            logger.error(f"Error verifying beacon from node_id={beacon.get('node_id', 'unknown')}: {e}")
            return False

    def run(self):
        """Run the beacon agent in a loop."""
        self.running = True
        logger.info(f"Starting beacon agent for node_id={self.node_id}")
        while self.running:
            try:
                beacon = self.create_beacon()
                if beacon:
                    self.broadcast_beacon(beacon)
                else:
                    logger.warning("Skipping broadcast due to beacon creation failure")
                time.sleep(self.interval)
            except Exception as e:
                logger.error(f"Beacon loop error: {e}")
                time.sleep(self.interval)

    def stop(self):
        """Stop the beacon agent."""
        self.running = False
        logger.info(f"Stopped beacon agent for node_id={self.node_id}")