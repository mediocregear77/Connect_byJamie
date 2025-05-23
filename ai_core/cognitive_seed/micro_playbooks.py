import time
import uuid
import threading
import logging
from dotenv import load_dotenv
import os
import redis
import cbor2
import boto3
from botocore.exceptions import ClientError
from audit_core.audit_log.qldb_logger import QLDBLogger
from security_core.pqc.dilithium import sign_message
from security_core.zk_snark.zkp import generate_zkp, verify_zkp
import hashlib

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/micro_playbooks.log')
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
APPROVAL_THRESHOLD = float(os.getenv('APPROVAL_THRESHOLD', 0.6))
MIN_VOTERS = int(os.getenv('MIN_VOTERS', 3))
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')
IOT_TOPIC_PREFIX = os.getenv('IOT_TOPIC_PREFIX', 'mesh')

class MicroPlaybook:
    """
    Represents a user-initiated micro-playbook for localized mesh action.
    """

    VALID_TYPES = ['reroute', 'drone_deploy', 'energy_save']
    PARAM_SCHEMAS = {
        'reroute': {'priority': str},
        'drone_deploy': {'location': str, 'count': int},
        'energy_save': {'mode': str}
    }

    def __init__(self, playbook_type, params, proposer):
        self.id = str(uuid.uuid4())
        self.type = playbook_type
        self.params = params
        self.proposer = proposer
        self.status = 'proposed'
        self.created_at = time.time()
        self.votes = {}
        self.approved = False
        self.lock = threading.Lock()
        self._validate()

    def _validate(self):
        """Validate playbook type and parameters."""
        with self.lock:
            try:
                if self.type not in self.VALID_TYPES:
                    logger.error(f"Invalid playbook type: {self.type}")
                    raise ValueError(f"Invalid playbook type: {self.type}")
                schema = self.PARAM_SCHEMAS.get(self.type, {})
                for key, expected_type in schema.items():
                    if key not in self.params or not isinstance(self.params[key], expected_type):
                        logger.error(f"Invalid params for {self.type}: {self.params}")
                        raise ValueError(f"Invalid params for {self.type}: {key}")
                
                # Log proposal to QLDB
                event_data = {
                    "playbook_id": self.id,
                    "type": self.type,
                    "proposer": self.proposer,
                    "signature": sign_message(cbor2.dumps({"playbook_id": self.id}))
                }
                QLDBLogger.log_event("playbook_proposal", event_data)
                logger.info(f"Proposed playbook: id={self.id}, type={self.type}")
            except Exception as e:
                logger.error(f"Playbook validation failed: {e}")
                raise

    def vote(self, node_id, approve, trust_score=1.0):
        """
        Cast a weighted vote for or against this micro-playbook.
        :param node_id: str
        :param approve: bool
        :param trust_score: float (node's trust score, default 1.0)
        """
        with self.lock:
            try:
                if not isinstance(node_id, str) or not node_id.strip() or not isinstance(approve, bool):
                    logger.warning(f"Invalid vote: node_id={node_id}, approve={approve}")
                    return False

                # Generate ZKP for vote integrity
                vote_data = {"node_id": node_id, "approve": approve, "playbook_id": self.id}
                zkp = generate_zkp(hashlib.sha3_512(cbor2.dumps(vote_data)).hexdigest())
                if not verify_zkp(hashlib.sha3_512(cbor2.dumps(vote_data)).hexdigest(), zkp):
                    logger.warning(f"ZKP verification failed for vote by node_id={node_id}")
                    return False

                self.votes[node_id] = {'approve': approve, 'trust_score': trust_score, 'zkp': zkp}
                
                # Log vote to QLDB
                event_data = {
                    "playbook_id": self.id,
                    "node_id": node_id,
                    "approve": approve,
                    "trust_score": trust_score,
                    "signature": sign_message(cbor2.dumps(vote_data))
                }
                QLDBLogger.log_event("playbook_vote", event_data)
                
                logger.info(f"Vote cast: playbook_id={self.id}, node_id={node_id}, approve={approve}")
                self._check_approval()
                return True
            except Exception as e:
                logger.error(f"Failed to process vote: {e}")
                return False

    def _check_approval(self):
        """Check if playbook meets weighted approval criteria."""
        with self.lock:
            try:
                if len(self.votes) < MIN_VOTERS:
                    return
                
                total_weight = sum(v['trust_score'] for v in self.votes.values())
                approval_weight = sum(v['trust_score'] for v in self.votes.values() if v['approve'])
                approval_ratio = approval_weight / total_weight if total_weight > 0 else 0.0

                if approval_ratio >= APPROVAL_THRESHOLD:
                    self.status = 'approved'
                    self.approved = True
                    
                    # Log approval to QLDB
                    event_data = {
                        "playbook_id": self.id,
                        "approval_ratio": approval_ratio,
                        "voter_count": len(self.votes),
                        "signature": sign_message(cbor2.dumps({"playbook_id": self.id}))
                    }
                    QLDBLogger.log_event("playbook_approval", event_data)
                    logger.info(f"Playbook approved: id={self.id}, approval_ratio={approval_ratio}")
            except Exception as e:
                logger.error(f"Failed to check approval: {e}")

    def execute(self, mesh_api):
        """
        Execute the playbook if approved via AWS IoT.
        :param mesh_api: interface to mesh node or controller
        """
        with self.lock:
            if not self.approved:
                logger.error(f"Playbook not approved: id={self.id}")
                raise Exception("Playbook not approved")

            try:
                self.status = 'executed'
                
                # Publish to AWS IoT
                iot_client = boto3.client('iot-data', region_name=AWS_REGION)
                topic = f"{IOT_TOPIC_PREFIX}/playbook/{self.id}"
                payload = {
                    "playbook_id": self.id,
                    "type": self.type,
                    "params": self.params
                }
                payload_bytes = cbor2.dumps(payload)
                signature = sign_message(payload_bytes)
                signed_payload = {'data': payload, 'signature': signature}

                iot_client.publish(
                    topic=topic,
                    qos=1,
                    payload=cbor2.dumps(signed_payload)
                )

                # Execute action (assumed mesh_api handles IoT integration)
                if self.type == 'reroute':
                    mesh_api.reroute(**self.params)
                elif self.type == 'drone_deploy':
                    mesh_api.deploy_drone(**self.params)
                elif self.type == 'energy_save':
                    mesh_api.set_energy_mode(**self.params)

                # Log execution to QLDB
                event_data = {
                    "playbook_id": self.id,
                    "type": self.type,
                    "signature": signature
                }
                QLDBLogger.log_event("playbook_execution", event_data)
                
                logger.info(f"Executed playbook: id={self.id}, type={self.type}")
            except ClientError as e:
                logger.error(f"AWS IoT publish error for playbook_id={self.id}: {e}")
                self.status = 'failed'
                raise
            except Exception as e:
                logger.error(f"Failed to execute playbook_id={self.id}: {e}")
                self.status = 'failed'
                raise

class MicroPlaybookManager:
    """
    Manages lifecycle of all micro-playbooks for a node.
    """

    def __init__(self):
        self.playbooks = {}
        self.lock = threading.Lock()
        self.redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)

    def propose(self, playbook_type, params, proposer):
        """Propose a new micro-playbook and cache it."""
        with self.lock:
            try:
                pb = MicroPlaybook(playbook_type, params, proposer)
                self.playbooks[pb.id] = pb
                
                # Cache playbook state
                cache_key = f"playbook_{pb.id}"
                self.redis_client.setex(cache_key, 86400, cbor2.dumps({
                    "id": pb.id,
                    "type": pb.type,
                    "params": pb.params,
                    "proposer": pb.proposer,
                    "status": pb.status
                }))
                
                logger.info(f"Proposed new playbook: id={pb.id}")
                return pb
            except Exception as e:
                logger.error(f"Failed to propose playbook: {e}")
                raise

    def get(self, playbook_id):
        """Retrieve a playbook with caching."""
        with self.lock:
            try:
                pb = self.playbooks.get(playbook_id)
                if pb:
                    return pb
                
                # Check Redis cache
                cache_key = f"playbook_{playbook_id}"
                cached_pb = self.redis_client.get(cache_key)
                if cached_pb:
                    pb_data = cbor2.loads(cached_pb)
                    pb = MicroPlaybook(pb_data['type'], pb_data['params'], pb_data['proposer'])
                    pb.id = pb_data['id']
                    pb.status = pb_data['status']
                    self.playbooks[playbook_id] = pb
                    logger.debug(f"Restored playbook from cache: id={playbook_id}")
                    return pb
                
                logger.warning(f"Playbook not found: id={playbook_id}")
                return None
            except Exception as e:
                logger.error(f"Failed to get playbook_id={playbook_id}: {e}")
                return None

    def vote(self, playbook_id, node_id, approve, trust_score=1.0):
        """Cast a vote for a playbook."""
        with self.lock:
            try:
                pb = self.get(playbook_id)
                if not pb:
                    logger.warning(f"Playbook not found for voting: id={playbook_id}")
                    return False
                
                pb.vote(node_id, approve, trust_score)
                
                # Update cache
                cache_key = f"playbook_{playbook_id}"
                self.redis_client.setex(cache_key, 86400, cbor2.dumps({
                    "id": pb.id,
                    "type": pb.type,
                    "params": pb.params,
                    "proposer": pb.proposer,
                    "status": pb.status
                }))
                
                return True
            except Exception as e:
                logger.error(f"Failed to vote on playbook_id={playbook_id}: {e}")
                return False

    def execute(self, playbook_id, mesh_api):
        """Execute an approved playbook."""
        with self.lock:
            try:
                pb = self.get(playbook_id)
                if not pb or pb.status != 'approved':
                    logger.warning(f"Cannot execute playbook_id={playbook_id}: not approved")
                    return False
                
                pb.execute(mesh_api)
                
                # Update cache
                cache_key = f"playbook_{playbook_id}"
                self.redis_client.setex(cache_key, 86400, cbor2.dumps({
                    "id": pb.id,
                    "type": pb.type,
                    "params": pb.params,
                    "proposer": pb.proposer,
                    "status": pb.status
                }))
                
                return True
            except Exception as e:
                logger.error(f"Failed to execute playbook_id={playbook_id}: {e}")
                return False

# Example usage
if __name__ == "__main__":
    class MockMeshAPI:
        def reroute(self, **params): print(f"Mock reroute: {params}")
        def deploy_drone(self, **params): print(f"Mock drone deploy: {params}")
        def set_energy_mode(self, **params): print(f"Mock energy mode: {params}")

    manager = MicroPlaybookManager()
    pb = manager.propose('reroute', {'priority': 'voice'}, 'user123')
    manager.vote(pb.id, 'nodeA', True, 1.0)
    manager.vote(pb.id, 'nodeB', True, 0.8)
    manager.vote(pb.id, 'nodeC', True, 0.9)
    if pb.status == 'approved':
        manager.execute(pb.id, MockMeshAPI())