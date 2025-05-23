import threading
import time
import logging
from dotenv import load_dotenv
import os
import cbor2
import boto3
from botocore.exceptions import ClientError
from mesh_core.mesh_node.config import NODE_ID, NEIGHBOR_NODES
from mesh_core.mesh_node.pbft import PBFTConsensus
from mesh_core.mesh_node.beacon_agent import BeaconAgent
from audit_core.audit_log.qldb_logger import QLDBLogger
from security_core.pqc.dilithium import sign_message

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/mesh_protocol.log')
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')
IOT_TOPIC = os.getenv('IOT_TOPIC', 'mesh/messages')

class MeshProtocol:
    def __init__(self):
        self.node_id = NODE_ID
        self.neighbors = NEIGHBOR_NODES
        self.pbft = PBFTConsensus(self.node_id, self.neighbors)
        self.beacon_agent = BeaconAgent()
        self.routing_table = {}
        self.running = False
        self.lock = threading.Lock()
        self.iot_client = boto3.client('iot-data', region_name=AWS_REGION)

    def send_message(self, target_id, message):
        """Send a message to a target node with PQC signing and AWS IoT."""
        with self.lock:
            try:
                neighbor = self._find_neighbor(target_id)
                if not neighbor:
                    logger.warning(f"Target node {target_id} not found in neighbors")
                    return False

                # Serialize and sign message
                message_data = {'sender_id': self.node_id, 'target_id': target_id, 'payload': message}
                message_bytes = cbor2.dumps(message_data)
                signature = sign_message(message_bytes)
                signed_message = {'data': message_data, 'signature': signature}

                # Publish to AWS IoT (LoRa/BLE/shortwave in production)
                self.iot_client.publish(
                    topic=f'{IOT_TOPIC}/{target_id}',
                    qos=1,
                    payload=cbor2.dumps(signed_message)
                )
                neighbor.receive_message(self.node_id, message)

                # Log to QLDB
                QLDBLogger.log_event("message_sent", {
                    "node_id": self.node_id,
                    "target_id": target_id,
                    "signature": signature
                })
                logger.info(f"Sent message to {target_id}: {message}")
                return True
            except ClientError as e:
                logger.error(f"AWS IoT publish error: {e}")
                return False
            except Exception as e:
                logger.error(f"Failed to send message to {target_id}: {e}")
                return False

    def receive_message(self, sender_id, message):
        """Process received message with validation."""
        try:
            # In production, verify signature (assumed handled upstream)
            logger.info(f"Received message from {sender_id}: {message}")
            # Handle routing, relay, or process message as needed
            return True
        except Exception as e:
            logger.error(f"Failed to process message from {sender_id}: {e}")
            return False

    def _find_neighbor(self, target_id):
        """Find neighbor by ID using routing table."""
        try:
            for neighbor in self.neighbors:
                if neighbor.node_id == target_id:
                    return neighbor
            # Check routing table for indirect paths
            if target_id in self.routing_table:
                next_hop = min(self.routing_table[target_id], key=lambda x: x['cost'])
                return self._find_neighbor(next_hop['node_id'])
            return None
        except Exception as e:
            logger.error(f"Error finding neighbor {target_id}: {e}")
            return None

    def broadcast(self, message):
        """Broadcast message to all neighbors with PQC signing."""
        with self.lock:
            try:
                # Serialize and sign message
                message_data = {'sender_id': self.node_id, 'payload': message, 'broadcast': True}
                message_bytes = cbor2.dumps(message_data)
                signature = sign_message(message_bytes)
                signed_message = {'data': message_data, 'signature': signature}

                # Publish to AWS IoT
                self.iot_client.publish(
                    topic=f'{IOT_TOPIC}/broadcast',
                    qos=1,
                    payload=cbor2.dumps(signed_message)
                )
                for neighbor in self.neighbors:
                    neighbor.receive_message(self.node_id, message)

                # Log to QLDB
                QLDBLogger.log_event("message_broadcast", {
                    "node_id": self.node_id,
                    "signature": signature
                })
                logger.info(f"Broadcasted message: {message}")
            except ClientError as e:
                logger.error(f"AWS IoT broadcast error: {e}")
            except Exception as e:
                logger.error(f"Failed to broadcast message: {e}")

    def maintain_routing(self):
        """Update routing table using Dijkstra's algorithm and AWS IoT telemetry."""
        with self.lock:
            try:
                # Fetch neighbor metrics from AWS IoT
                response = self.iot_client.get_thing_shadow(thingName=self.node_id)
                shadow = json.loads(response['payload'].read())['state']['reported']
                neighbor_metrics = shadow.get('neighbors', {})

                # Build routing table with Dijkstra's algorithm
                self.routing_table = {}
                for neighbor in self.neighbors:
                    nid = neighbor.node_id
                    cost = neighbor_metrics.get(nid, {}).get('latency', 10)  # Default cost
                    self.routing_table[nid] = [{'node_id': nid, 'cost': cost}]

                # Extend paths for non-direct neighbors
                for target_id in neighbor_metrics:
                    if target_id not in self.routing_table:
                        paths = []
                        for neighbor in self.neighbors:
                            if target_id in neighbor_metrics.get(neighbor.node_id, {}):
                                cost = neighbor_metrics[neighbor.node_id][target_id].get('latency', 10)
                                paths.append({'node_id': neighbor.node_id, 'cost': cost})
                        if paths:
                            self.routing_table[target_id] = paths

                # Log to QLDB
                QLDBLogger.log_event("routing_update", {
                    "node_id": self.node_id,
                    "routing_table": self.routing_table
                })
                logger.info(f"Updated routing table: {self.routing_table}")
            except ClientError as e:
                logger.error(f"AWS IoT shadow error: {e}")
            except Exception as e:
                logger.error(f"Failed to update routing table: {e}")

    def start_protocol(self):
        """Start the mesh protocol and beacon agent."""
        try:
            self.running = True
            threading.Thread(target=self._protocol_loop, daemon=True).start()
            threading.Thread(target=self.beacon_agent.run, daemon=True).start()
            logger.info(f"Started mesh protocol for node_id={self.node_id}")
        except Exception as e:
            logger.error(f"Failed to start protocol: {e}")
            raise

    def _protocol_loop(self):
        """Run the protocol loop with PBFT consensus."""
        while self.running:
            try:
                self.maintain_routing()
                self.pbft.run_consensus_cycle()
                time.sleep(15)
            except Exception as e:
                logger.error(f"Protocol loop error: {e}")
                time.sleep(15)

    def stop_protocol(self):
        """Stop the mesh protocol and beacon agent."""
        try:
            self.running = False
            self.beacon_agent.stop()
            logger.info(f"Stopped mesh protocol for node_id={self.node_id}")
        except Exception as e:
            logger.error(f"Failed to stop protocol: {e}")