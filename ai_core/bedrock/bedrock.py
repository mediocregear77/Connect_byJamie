import torch
import logging
import threading
from dotenv import load_dotenv
import os
import redis
import cbor2
import boto3
from botocore.exceptions import ClientError
from .playbook_synth import PlaybookSynth
from .mesh_law import MeshLaw
from .trust_market import TrustMarket
from .anomaly_gnn import AnomalyGNN
from audit_core.audit_log.qldb_logger import QLDBLogger
from security_core.pqc.dilithium import sign_message
import hashlib
import time

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/bedrock.log')
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')
IOT_TOPIC_PREFIX = os.getenv('IOT_TOPIC_PREFIX', 'mesh')
BATCH_SIZE = int(os.getenv('BEDROCK_BATCH_SIZE', 100))

class Bedrock:
    def __init__(self, config):
        self.config = config
        self.lock = threading.Lock()
        self.redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
        self.iot_client = boto3.client('iot-data', region_name=AWS_REGION)
        self.playbook_synth = PlaybookSynth(config)
        self.mesh_law = MeshLaw(config)
        self.trust_market = TrustMarket(config)
        self.anomaly_gnn = AnomalyGNN(config)

    def synthesize_playbook(self, context, retries=3):
        """Synthesize a playbook with retry logic and QLDB logging."""
        with self.lock:
            if not isinstance(context, dict):
                logger.warning(f"Invalid context: {context}")
                raise ValueError("Context must be a dictionary")

            try:
                cache_key = f"playbook_{hashlib.sha3_512(cbor2.dumps(context)).hexdigest()}"
                cached_playbook = self.redis_client.get(cache_key)
                if cached_playbook:
                    logger.debug("Returning cached playbook")
                    return json.loads(cached_playbook)

                for attempt in range(retries):
                    try:
                        playbook = self.playbook_synth.generate(context)
                        
                        # Log to QLDB
                        event_data = {
                            "context_hash": hashlib.sha3_512(cbor2.dumps(context)).hexdigest(),
                            "playbook": playbook,
                            "signature": sign_message(cbor2.dumps(playbook))
                        }
                        QLDBLogger.log_event("playbook_synthesis", event_data)

                        # Cache for 300 seconds
                        self.redis_client.setex(cache_key, 300, json.dumps(playbook))
                        logger.info(f"Synthesized playbook for context")
                        return playbook
                    except Exception as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for playbook synthesis: {e}")
                            time.sleep(2 ** attempt)  # Exponential backoff
                        else:
                            logger.error(f"Failed to synthesize playbook after {retries} attempts: {e}")
                            raise
            except Exception as e:
                logger.error(f"Playbook synthesis failed: {e}")
                raise

    def enforce_mesh_law(self, event, retries=3):
        """Enforce mesh law with retry logic and QLDB logging."""
        with self.lock:
            if not isinstance(event, dict):
                logger.warning(f"Invalid event: {event}")
                raise ValueError("Event must be a dictionary")

            try:
                cache_key = f"law_{hashlib.sha3_512(cbor2.dumps(event)).hexdigest()}"
                cached_result = self.redis_client.get(cache_key)
                if cached_result:
                    logger.debug("Returning cached mesh law result")
                    return json.loads(cached_result)

                for attempt in range(retries):
                    try:
                        result = self.mesh_law.apply(event)
                        
                        # Log to QLDB
                        event_data = {
                            "event_hash": hashlib.sha3_512(cbor2.dumps(event)).hexdigest(),
                            "result": result,
                            "signature": sign_message(cbor2.dumps(result))
                        }
                        QLDBLogger.log_event("mesh_law_enforcement", event_data)

                        # Cache for 300 seconds
                        self.redis_client.setex(cache_key, 300, json.dumps(result))
                        logger.info(f"Enforced mesh law for event")
                        return result
                    except Exception as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for mesh law enforcement: {e}")
                            time.sleep(2 ** attempt)  # Exponential backoff
                        else:
                            logger.error(f"Failed to enforce mesh law after {retries} attempts: {e}")
                            raise
            except Exception as e:
                logger.error(f"Mesh law enforcement failed: {e}")
                raise

    def calculate_trust(self, node_metrics, retries=3):
        """Calculate trust scores with retry logic and QLDB logging."""
        with self.lock:
            if not isinstance(node_metrics, (list, dict)):
                logger.warning(f"Invalid node metrics: {node_metrics}")
                raise ValueError("Node metrics must be a list or dictionary")

            try:
                cache_key = f"trust_{hashlib.sha3_512(cbor2.dumps(node_metrics)).hexdigest()}"
                cached_scores = self.redis_client.get(cache_key)
                if cached_scores:
                    logger.debug("Returning cached trust scores")
                    return json.loads(cached_scores)

                for attempt in range(retries):
                    try:
                        scores = self.trust_market.evaluate(node_metrics)
                        
                        # Log to QLDB
                        event_data = {
                            "metrics_hash": hashlib.sha3_512(cbor2.dumps(node_metrics)).hexdigest(),
                            "scores": scores,
                            "signature": sign_message(cbor2.dumps(scores))
                        }
                        QLDBLogger.log_event("trust_calculation", event_data)

                        # Cache for 300 seconds
                        self.redis_client.setex(cache_key, 300, json.dumps(scores))
                        logger.info(f"Calculated trust scores for {len(node_metrics)} nodes")
                        return scores
                    except Exception as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for trust calculation: {e}")
                            time.sleep(2 ** attempt)  # Exponential backoff
                        else:
                            logger.error(f"Failed to calculate trust after {retries} attempts: {e}")
                            raise
            except Exception as e:
                logger.error(f"Trust calculation failed: {e}")
                raise

    def detect_anomaly(self, network_snapshot, retries=3):
        """Detect anomalies with retry logic and QLDB logging."""
        with self.lock:
            if not isinstance(network_snapshot, dict):
                logger.warning(f"Invalid network snapshot: {network_snapshot}")
                raise ValueError("Network snapshot must be a dictionary")

            try:
                cache_key = f"anomaly_{hashlib.sha3_512(cbor2.dumps(network_snapshot)).hexdigest()}"
                cached_anomalies = self.redis_client.get(cache_key)
                if cached_anomalies:
                    logger.debug("Returning cached anomalies")
                    return json.loads(cached_anomalies)

                for attempt in range(retries):
                    try:
                        anomalies = self.anomaly_gnn.detect(network_snapshot)
                        
                        # Log to QLDB
                        event_data = {
                            "snapshot_hash": hashlib.sha3_512(cbor2.dumps(network_snapshot)).hexdigest(),
                            "anomaly_count": len(anomalies),
                            "signature": sign_message(cbor2.dumps({"anomaly_count": len(anomalies)}))
                        }
                        QLDBLogger.log_event("anomaly_detection", event_data)

                        # Cache for 300 seconds
                        self.redis_client.setex(cache_key, 300, json.dumps(anomalies))
                        logger.info(f"Detected {len(anomalies)} anomalies in network snapshot")
                        return anomalies
                    except Exception as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for anomaly detection: {e}")
                            time.sleep(2 ** attempt)  # Exponential backoff
                        else:
                            logger.error(f"Failed to detect anomalies after {retries} attempts: {e}")
                            raise
            except Exception as e:
                logger.error(f"Anomaly detection failed: {e}")
                raise

    def run_cycle(self, mesh_data, event_log, batch_size=BATCH_SIZE):
        """Main processing loop for Bedrock AI Core with batch processing."""
        with self.lock:
            if not isinstance(mesh_data, dict) or not isinstance(event_log, list):
                logger.warning(f"Invalid input: mesh_data={type(mesh_data)}, event_log={type(event_log)}")
                raise ValueError("Mesh data must be a dictionary and event log a list")

            try:
                # Batch process nodes for trust calculation
                nodes = mesh_data.get('nodes', [])
                trust_scores = []
                for i in range(0, len(nodes), batch_size):
                    batch = nodes[i:i + batch_size]
                    trust_scores.extend(self.calculate_trust(batch))

                # Batch process events for law enforcement
                legal_events = []
                for i in range(0, len(event_log), batch_size):
                    batch = event_log[i:i + batch_size]
                    legal_events.extend([self.enforce_mesh_law(event) for event in batch])

                # Detect anomalies and synthesize playbook
                anomalies = self.detect_anomaly(mesh_data)
                playbook = self.synthesize_playbook(mesh_data)

                # Publish results to AWS IoT
                result = {
                    "anomalies": anomalies,
                    "trust_scores": trust_scores,
                    "legal_events": legal_events,
                    "playbook": playbook
                }
                result_bytes = cbor2.dumps(result)
                signature = sign_message(result_bytes)
                signed_result = {'data': result, 'signature': signature}

                self.iot_client.publish(
                    topic=f"{IOT_TOPIC_PREFIX}/bedrock/cycle",
                    qos=1,
                    payload=cbor2.dumps(signed_result)
                )

                # Log to QLDB
                event_data = {
                    "cycle_hash": hashlib.sha3_512(result_bytes).hexdigest(),
                    "anomaly_count": len(anomalies),
                    "node_count": len(trust_scores),
                    "event_count": len(legal_events),
                    "signature": signature
                }
                QLDBLogger.log_event("bedrock_cycle", event_data)

                logger.info(f"Completed Bedrock cycle: anomalies={len(anomalies)}, nodes={len(trust_scores)}")
                return result
            except ClientError as e:
                logger.error(f"AWS IoT publish error in Bedrock cycle: {e}")
                raise
            except Exception as e:
                logger.error(f"Bedrock cycle failed: {e}")
                raise

# Example usage
if __name__ == "__main__":
    config = {"mode": "production"}
    bedrock = Bedrock(config)
    mesh_data = {"nodes": [{"id": "node-001", "latency": 50}, {"id": "node-002", "latency": 60}]}
    event_log = [{"type": "connect", "node": "node-001"}]
    result = bedrock.run_cycle(mesh_data, event_log)
    print(result)