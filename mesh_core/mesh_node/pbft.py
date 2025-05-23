import threading
import time
import logging
from dotenv import load_dotenv
import os
import cbor2
import boto3
from botocore.exceptions import ClientError
from audit_core.audit_log.qldb_logger import QLDBLogger
from security_core.pqc.dilithium import sign_message

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/pbft.log')
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')
IOT_TOPIC = os.getenv('IOT_TOPIC', 'mesh/pbft')
CONSENSUS_INTERVAL = int(os.getenv('CONSENSUS_INTERVAL', 15))

class PBFTConsensus:
    def __init__(self, node_id, neighbors):
        self.node_id = node_id
        self.neighbors = neighbors  # List of neighbor node objects
        self.current_leader = None
        self.view_number = 0
        self.state = 'IDLE'
        self.last_decision = None
        self.lock = threading.Lock()
        self.iot_client = boto3.client('iot-data', region_name=AWS_REGION)
        self.pending_messages = {}  # Stage: {value: [sender_ids]}

    def propose(self, value):
        """Initiate consensus on a value with PQC signing."""
        with self.lock:
            try:
                self.state = 'PRE-PREPARE'
                self.current_leader = self._select_leader()
                if self.current_leader != self.node_id:
                    logger.warning(f"Node {self.node_id} is not the leader, aborting proposal")
                    return

                # Serialize and sign proposal
                proposal = {'node_id': self.node_id, 'value': value, 'view_number': self.view_number}
                proposal_bytes = cbor2.dumps(proposal)
                signature = sign_message(proposal_bytes)
                signed_proposal = {'data': proposal, 'signature': signature}

                # Broadcast via AWS IoT
                self._broadcast('PRE-PREPARE', signed_proposal)
                logger.info(f"Proposed value: {value} (Leader: {self.current_leader}, View: {self.view_number})")

                # Log to QLDB
                QLDBLogger.log_event("pbft_propose", {
                    "node_id": self.node_id,
                    "value": value,
                    "view_number": self.view_number,
                    "signature": signature
                })

                self._prepare(value)
            except Exception as e:
                logger.error(f"Failed to propose value: {e}")
                self.state = 'IDLE'

    def _prepare(self, value):
        """Handle PREPARE phase with majority verification."""
        with self.lock:
            try:
                self.state = 'PREPARE'
                self.pending_messages.setdefault('PREPARE', {}).setdefault(value, []).append(self.node_id)
                
                # Broadcast PREPARE message
                message = {'node_id': self.node_id, 'value': value, 'view_number': self.view_number}
                message_bytes = cbor2.dumps(message)
                signature = sign_message(message_bytes)
                signed_message = {'data': message, 'signature': signature}
                self._broadcast('PREPARE', signed_message)

                # Check for 2f+1 PREPARE messages (f = max faulty nodes)
                if len(self.pending_messages['PREPARE'].get(value, [])) >= (2 * (len(self.neighbors) // 3) + 1):
                    self._commit(value)
                logger.info(f"PREPARE phase for value: {value}")
            except Exception as e:
                logger.error(f"Failed in PREPARE phase: {e}")
                self.state = 'IDLE'

    def _commit(self, value):
        """Handle COMMIT phase with majority verification."""
        with self.lock:
            try:
                self.state = 'COMMIT'
                self.pending_messages.setdefault('COMMIT', {}).setdefault(value, []).append(self.node_id)
                
                # Broadcast COMMIT message
                message = {'node_id': self.node_id, 'value': value, 'view_number': self.view_number}
                message_bytes = cbor2.dumps(message)
                signature = sign_message(message_bytes)
                signed_message = {'data': message, 'signature': signature}
                self._broadcast('COMMIT', signed_message)

                # Check for 2f+1 COMMIT messages
                if len(self.pending_messages['COMMIT'].get(value, [])) >= (2 * (len(self.neighbors) // 3) + 1):
                    self.last_decision = value
                    self.state = 'IDLE'
                    logger.info(f"Consensus reached on value: {value}")
                    
                    # Log to QLDB
                    QLDBLogger.log_event("pbft_commit", {
                        "node_id": self.node_id,
                        "value": value,
                        "view_number": self.view_number
                    })
            except Exception as e:
                logger.error(f"Failed in COMMIT phase: {e}")
                self.state = 'IDLE'

    def _broadcast(self, stage, message):
        """Broadcast PBFT message via AWS IoT."""
        try:
            self.iot_client.publish(
                topic=f'{IOT_TOPIC}/{stage}/{self.node_id}',
                qos=1,
                payload=cbor2.dumps(message)
            )
            for neighbor in self.neighbors:
                neighbor.receive_pbft(self.node_id, stage, message)
            logger.debug(f"Broadcasted {stage} message for node_id={self.node_id}")
        except ClientError as e:
            logger.error(f"AWS IoT broadcast error: {e}")
        except Exception as e:
            logger.error(f"Failed to broadcast {stage} message: {e}")

    def receive_pbft(self, sender_id, stage, message):
        """Process received PBFT message."""
        try:
            # Extract and verify message
            data = message['data']
            value = data['value']
            view_number = data['view_number']
            signature = message['signature']

            # Verify signature (assumed Dilithium)
            if not verify_signature(cbor2.dumps(data), signature, sender_id):
                logger.warning(f"Invalid signature from {sender_id} for {stage}")
                return

            if view_number != self.view_number:
                logger.warning(f"Mismatched view number from {sender_id}: {view_number}")
                return

            # Update pending messages
            with self.lock:
                self.pending_messages.setdefault(stage, {}).setdefault(value, []).append(sender_id)
                logger.info(f"Received {stage} from {sender_id}: {value}")

                # Process based on stage
                if stage == 'PRE-PREPARE' and self.state == 'IDLE':
                    self.state = 'PRE-PREPARE'
                    self._prepare(value)
                elif stage == 'PREPARE' and self.state == 'PREPARE':
                    if len(self.pending_messages['PREPARE'].get(value, [])) >= (2 * (len(self.neighbors) // 3) + 1):
                        self._commit(value)
                elif stage == 'COMMIT' and self.state == 'COMMIT':
                    if len(self.pending_messages['COMMIT'].get(value, [])) >= (2 * (len(self.neighbors) // 3) + 1):
                        self.last_decision = value
                        self.state = 'IDLE'
                        logger.info(f"Consensus reached on value: {value}")
        except Exception as e:
            logger.error(f"Error processing PBFT message from {sender_id}: {e}")

    def _select_leader(self):
        """Select leader based on view number."""
        try:
            all_nodes = [self.node_id] + [n.node_id for n in self.neighbors]
            all_nodes.sort()
            idx = self.view_number % len(all_nodes)
            leader = all_nodes[idx]
            logger.debug(f"Selected leader: {leader} for view_number={self.view_number}")
            return leader
        except Exception as e:
            logger.error(f"Failed to select leader: {e}")
            return self.node_id

    def run_consensus_cycle(self):
        """Run a PBFT consensus cycle with real mesh data."""
        try:
            # Fetch mesh state from AWS IoT
            response = self.iot_client.get_thing_shadow(thingName=self.node_id)
            shadow = json.loads(response['payload'].read())['state']['reported']
            routing_table = shadow.get('routing_table', {})

            if self._select_leader() == self.node_id:
                # Propose routing table update
                value = {'routing_table': routing_table}
                self.propose(value)
            else:
                logger.debug(f"Waiting for leader proposal in view_number={self.view_number}")
            self.view_number += 1
            time.sleep(CONSENSUS_INTERVAL)
        except ClientError as e:
            logger.error(f"AWS IoT shadow error: {e}")
        except Exception as e:
            logger.error(f"Consensus cycle error: {e}")