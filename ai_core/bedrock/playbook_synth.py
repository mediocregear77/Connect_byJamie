import logging
import threading
from dotenv import load_dotenv
import os
import redis
import cbor2
import boto3
from botocore.exceptions import ClientError
from audit_core.audit_log.qldb_logger import QLDBLogger
from security_core.pqc.dilithium import sign_message
import hashlib
import json

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/playbook_synth.log')
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')
IOT_TOPIC_PREFIX = os.getenv('IOT_TOPIC_PREFIX', 'mesh')
PRIORITY_WEIGHTS = json.loads(os.getenv('PLAYBOOK_PRIORITY_WEIGHTS', '{"critical": 1.0, "community": 0.8, "normal": 0.5}'))

class PlaybookSynth:
    def __init__(self, config):
        self.config = config
        self.lock = threading.Lock()
        self.redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
        self.iot_client = boto3.client('iot-data', region_name=AWS_REGION)

    def generate(self, context):
        """
        Synthesize a playbook based on mesh state, threat context, and user feedback.
        """
        with self.lock:
            if not isinstance(context, dict):
                logger.warning(f"Invalid context: {context}")
                raise ValueError("Context must be a dictionary")

            try:
                # Cache playbook based on context hash
                context_hash = hashlib.sha3_512(cbor2.dumps(context)).hexdigest()
                cache_key = f"playbook_{context_hash}"
                cached_playbook = self.redis_client.get(cache_key)
                if cached_playbook:
                    logger.debug("Returning cached playbook")
                    return json.loads(cached_playbook)

                playbook = []

                # Rule 1: Handle anomalies (integrate with anomaly_gnn.py)
                if "anomalies" in context and context["anomalies"]:
                    severity = context.get("anomaly_severity", 1.0)
                    if severity > 0.7:  # High-severity anomalies
                        playbook.append({
                            "action": "resonance_cascade",
                            "target": context["anomalies"],
                            "priority": "critical",
                            "weight": PRIORITY_WEIGHTS.get("critical", 1.0)
                        })
                    else:  # Moderate anomalies
                        playbook.append({
                            "action": "reroute",
                            "target": context["anomalies"],
                            "priority": "normal",
                            "weight": PRIORITY_WEIGHTS.get("normal", 0.5)
                        })

                # Rule 2: Process community micro-playbook requests (integrate with micro_playbooks.py)
                if "user_requests" in context and context["user_requests"]:
                    for req in context["user_requests"]:
                        if not isinstance(req, dict) or "action" not in req or "target" not in req:
                            logger.warning(f"Invalid user request: {req}")
                            continue
                        playbook.append({
                            "action": req["action"],
                            "target": req["target"],
                            "priority": "community",
                            "weight": PRIORITY_WEIGHTS.get("community", 0.8)
                        })

                # Rule 3: Low trust nodes (integrate with trust_market.py)
                if "trust_scores" in context and context["trust_scores"]:
                    low_trust_nodes = [node for node, score in context["trust_scores"].items() if score < 0.5]
                    if low_trust_nodes:
                        playbook.append({
                            "action": "quarantine",
                            "target": low_trust_nodes,
                            "priority": "critical",
                            "weight": PRIORITY_WEIGHTS.get("critical", 1.0)
                        })

                # Default fallback: Maintain mesh health
                if not playbook:
                    playbook.append({
                        "action": "monitor",
                        "target": "all",
                        "priority": "normal",
                        "weight": PRIORITY_WEIGHTS.get("normal", 0.5)
                    })

                # Sort playbook by weight for prioritization
                playbook.sort(key=lambda x: x["weight"], reverse=True)

                # Publish playbook to AWS IoT
                payload = {"playbook": playbook, "context_hash": context_hash}
                payload_bytes = cbor2.dumps(payload)
                signature = sign_message(payload_bytes)
                signed_payload = {'data': payload, 'signature': signature}

                self.iot_client.publish(
                    topic=f"{IOT_TOPIC_PREFIX}/playbook/synth",
                    qos=1,
                    payload=cbor2.dumps(signed_payload)
                )

                # Log to QLDB
                event_data = {
                    "context_hash": context_hash,
                    "playbook_size": len(playbook),
                    "signature": signature
                }
                QLDBLogger.log_event("playbook_generation", event_data)

                # Cache playbook for 300 seconds
                self.redis_client.setex(cache_key, 300, json.dumps(playbook))
                logger.info(f"Generated playbook with {len(playbook)} actions")
                return playbook
            except ClientError as e:
                logger.error(f"AWS IoT publish error: {e}")
                raise
            except Exception as e:
                logger.error(f"Failed to generate playbook: {e}")
                raise