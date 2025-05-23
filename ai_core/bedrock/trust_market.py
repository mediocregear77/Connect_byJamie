import hashlib
import json
import logging
import threading
from collections import defaultdict
from dotenv import load_dotenv
import os
import redis
import cbor2
import boto3
from botocore.exceptions import ClientError
from audit_core.audit_log.qldb_logger import QLDBLogger
from security_core.pqc.dilithium import sign_message
from security_core.zk_snark.zkp import generate_zkp, verify_zkp
import time
from jsonschema import validate, ValidationError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/trust_market.log')
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
TRUST_DATA_PATH = os.getenv('TRUST_DATA_PATH', '/data/trust_scores.json')
AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')
SSM_PARAMETER_PATH = os.getenv('SSM_TRUST_SCORES_PATH', '/mesh/trust/scores')
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
IOT_TOPIC_PREFIX = os.getenv('IOT_TOPIC_PREFIX', 'mesh')
DECAY_RATE = float(os.getenv('TRUST_DECAY_RATE', 0.01))  # Daily decay for inactive nodes
ACTION_WEIGHTS = json.loads(os.getenv('TRUST_ACTION_WEIGHTS', '{"beacon_valid": 1, "playbook": 2, "lighthouse": 3, "invalid": -5}'))

# JSON schema for trust scores
TRUST_SCORE_SCHEMA = {
    "type": "object",
    "properties": {
        "score": {"type": "number"},
        "beacon_validations": {"type": "integer", "minimum": 0},
        "playbook_contributions": {"type": "integer", "minimum": 0},
        "lighthouse_reports": {"type": "integer", "minimum": 0},
        "last_updated": {"type": "number", "minimum": 0}
    },
    "required": ["score", "beacon_validations", "playbook_contributions", "lighthouse_reports", "last_updated"]
}

class TrustMarket:
    def __init__(self, trust_data_path=TRUST_DATA_PATH):
        self.trust_data_path = trust_data_path
        self.trust_scores = None
        self.lock = threading.Lock()
        self.redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
        self.ssm_client = boto3.client('ssm', region_name=AWS_REGION)
        self.iot_client = boto3.client('iot-data', region_name=AWS_REGION)
        self.load_trust_scores()

    def load_trust_scores(self):
        """Load trust scores from SSM or local JSON with caching."""
        with self.lock:
            try:
                cache_key = "trust_scores"
                cached_scores = self.redis_client.get(cache_key)
                if cached_scores:
                    self.trust_scores = json.loads(cached_scores)
                    logger.debug("Returning cached trust scores")
                    return

                # Try AWS SSM Parameter Store first
                try:
                    response = self.ssm_client.get_parameter(
                        Name=SSM_PARAMETER_PATH,
                        WithDecryption=True
                    )
                    self.trust_scores = json.loads(response['Parameter']['Value'])
                    logger.info("Loaded trust scores from AWS SSM Parameter Store")
                except ClientError as e:
                    logger.warning(f"SSM error, falling back to local JSON: {e}")
                    if not os.path.exists(self.trust_data_path):
                        logger.info(f"Trust data file not found: {self.trust_data_path}, using defaults")
                        self.trust_scores = defaultdict(lambda: {
                            "score": 0,
                            "beacon_validations": 0,
                            "playbook_contributions": 0,
                            "lighthouse_reports": 0,
                            "last_updated": time.time()
                        })
                    else:
                        with open(self.trust_data_path, 'r') as f:
                            self.trust_scores = json.load(f)

                # Validate scores
                for node_id, score_data in self.trust_scores.items():
                    validate(instance=score_data, schema=TRUST_SCORE_SCHEMA)

                # Cache scores for 300 seconds
                self.redis_client.setex(cache_key, 300, json.dumps(self.trust_scores))

                # Log to QLDB
                event_data = {
                    "scores_hash": self.verify_integrity(),
                    "signature": sign_message(cbor2.dumps({"scores_hash": self.verify_integrity()}))
                }
                QLDBLogger.log_event("trust_scores_load", event_data)

                logger.info(f"Loaded trust scores from {self.trust_data_path or 'SSM'}")
            except ValidationError as e:
                logger.error(f"Invalid trust score data: {e}")
                raise
            except Exception as e:
                logger.error(f"Failed to load trust scores: {e}")
                raise

    def update_score(self, node_id, action, delta=1, context=None, retries=3):
        """Update a node's trust score with weighted contributions and decay."""
        with self.lock:
            if not isinstance(node_id, str) or not node_id.strip() or action not in ACTION_WEIGHTS:
                logger.warning(f"Invalid input: node_id={node_id}, action={action}")
                raise ValueError("Invalid node_id or action")

            try:
                if not self.trust_scores:
                    self.load_trust_scores()

                node_score = self.trust_scores.get(node_id, {
                    "score": 0,
                    "beacon_validations": 0,
                    "playbook_contributions": 0,
                    "lighthouse_reports": 0,
                    "last_updated": time.time()
                })

                # Apply trust decay based on time since last update
                elapsed_days = (time.time() - node_score["last_updated"]) / (24 * 3600)
                node_score["score"] *= (1 - DECAY_RATE) ** elapsed_days

                # Adjust score based on action and context
                weight = ACTION_WEIGHTS[action]
                if context:
                    severity = context.get("severity", 1.0)  # E.g., anomaly severity from anomaly_gnn.py
                    weight *= severity

                if action == "beacon_valid":
                    node_score["score"] += delta * weight
                    node_score["beacon_validations"] += 1
                elif action == "playbook":
                    node_score["score"] += delta * weight
                    node_score["playbook_contributions"] += 1
                elif action == "lighthouse":
                    node_score["score"] += delta * weight
                    node_score["lighthouse_reports"] += 1
                elif action == "invalid":
                    node_score["score"] -= abs(delta) * weight

                # Ensure score stays within bounds (e.g., 0-100)
                node_score["score"] = max(0, min(100, node_score["score"]))
                node_score["last_updated"] = time.time()

                # Generate ZKP for score integrity
                score_data = {k: v for k, v in node_score.items()}
                score_hash = hashlib.sha3_512(cbor2.dumps(score_data)).hexdigest()
                zkp = generate_zkp(score_hash)
                if not verify_zkp(score_hash, zkp):
                    logger.warning(f"ZKP verification failed for node_id={node_id}")
                    return False

                self.trust_scores[node_id] = score_data

                # Persist with retries
                for attempt in range(retries):
                    try:
                        self._persist()
                        break
                    except ClientError as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for trust score persistence: {e}")
                            time.sleep(2 ** attempt)  # Exponential backoff
                        else:
                            logger.error(f"Failed to persist trust scores after {retries} attempts: {e}")
                            return False

                # Publish update to AWS IoT
                payload = {"node_id": node_id, "action": action, "score": node_score["score"]}
                payload_bytes = cbor2.dumps(payload)
                signature = sign_message(payload_bytes)
                signed_payload = {'data': payload, 'signature': signature}

                self.iot_client.publish(
                    topic=f"{IOT_TYPE_PREFIX}/trust/update",
                    qos=1,
                    payload=cbor2.dumps(signed_payload)
                )

                # Log to QLDB
                event_data = {
                    "node_id": node_id,
                    "action": action,
                    "score": node_score["score"],
                    "signature": signature
                }
                QLDBLogger.log_event("trust_score_update", event_data)

                # Update cache
                cache_key = "trust_scores"
                self.redis_client.setex(cache_key, 300, json.dumps(self.trust_scores))

                logger.info(f"Updated trust score for node_id={node_id}: score={node_score['score']}")
                return True
            except ClientError as e:
                logger.error(f"AWS IoT publish error for node_id={node_id}: {e}")
                raise
            except Exception as e:
                logger.error(f"Failed to update score for node_id={node_id}: {e}")
                raise

    def get_score(self, node_id):
        """Retrieve the current trust score for a node."""
        with self.lock:
            try:
                if not isinstance(node_id, str) or not node_id.strip():
                    logger.warning(f"Invalid node_id: {node_id}")
                    raise ValueError("Invalid node_id")

                if not self.trust_scores:
                    self.load_trust_scores()

                score_data = self.trust_scores.get(node_id, {
                    "score": 0,
                    "beacon_validations": 0,
                    "playbook_contributions": 0,
                    "lighthouse_reports": 0,
                    "last_updated": time.time()
                })

                # Log to QLDB
                event_data = {
                    "node_id": node_id,
                    "score": score_data["score"],
                    "signature": sign_message(cbor2.dumps({"node_id": node_id, "score": score_data["score"]}))
                }
                QLDBLogger.log_event("trust_score_get", event_data)

                logger.debug(f"Retrieved trust score for node_id={node_id}: score={score_data['score']}")
                return score_data
            except Exception as e:
                logger.error(f"Failed to get score for node_id={node_id}: {e}")
                return {"score": 0}

    def leaderboard(self, top_n=10):
        """Return the top N nodes by trust score."""
        with self.lock:
            try:
                if not isinstance(top_n, int) or top_n < 1:
                    logger.warning(f"Invalid top_n: {top_n}")
                    raise ValueError("Invalid top_n")

                if not self.trust_scores:
                    self.load_trust_scores()

                cache_key = f"trust_leaderboard_{top_n}"
                cached_leaderboard = self.redis_client.get(cache_key)
                if cached_leaderboard:
                    logger.debug("Returning cached leaderboard")
                    return json.loads(cached_leaderboard)

                leaderboard = sorted(
                    self.trust_scores.items(),
                    key=lambda x: x[1]['score'],
                    reverse=True
                )[:top_n]

                # Log to QLDB
                event_data = {
                    "top_n": top_n,
                    "leaderboard_size": len(leaderboard),
                    "signature": sign_message(cbor2.dumps({"top_n": top_n}))
                }
                QLDBLogger.log_event("trust_leaderboard", event_data)

                # Cache for 300 seconds
                self.redis_client.setex(cache_key, 300, json.dumps(leaderboard))
                logger.info(f"Generated leaderboard for top_n={top_n}: {len(leaderboard)} nodes")
                return leaderboard
            except Exception as e:
                logger.error(f"Failed to generate leaderboard: {e}")
                return []

    def _persist(self):
        """Persist trust scores to local JSON and SSM."""
        try:
            # Save to local JSON
            with open(self.trust_data_path, 'w') as f:
                json.dump(self.trust_scores, f, indent=2)

            # Save to SSM Parameter Store
            self.ssm_client.put_parameter(
                Name=SSM_PARAMETER_PATH,
                Value=json.dumps(self.trust_scores),
                Type='SecureString',
                Overwrite=True
            )

            logger.debug("Persisted trust scores to local JSON and SSM")
        except ClientError as e:
            logger.error(f"SSM persistence error: {e}")
            raise
        except Exception as e:
            logger.error(f"Failed to persist trust scores: {e}")
            raise

    def verify_integrity(self):
        """Generate a Merkle root hash for current trust scores with ZKP."""
        with self.lock:
            try:
                if not self.trust_scores:
                    self.load_trust_scores()

                scores_str = json.dumps(self.trust_scores, sort_keys=True)
                merkle_hash = hashlib.sha3_512(scores_str.encode('utf-8')).hexdigest()

                # Generate ZKP for hash integrity
                zkp = generate_zkp(merkle_hash)
                if not verify_zkp(merkle_hash, zkp):
                    logger.warning("ZKP verification failed for trust scores")
                    return None

                # Log to QLDB
                event_data = {
                    "merkle_hash": merkle_hash,
                    "signature": sign_message(cbor2.dumps({"merkle_hash": merkle_hash}))
                }
                QLDBLogger.log_event("trust_integrity_verify", event_data)

                logger.info(f"Verified trust scores integrity: merkle_hash={merkle_hash[:16]}...")
                return merkle_hash
            except Exception as e:
                logger.error(f"Failed to verify trust scores integrity: {e}")
                return None