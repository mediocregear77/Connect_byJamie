import json
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
from security_core.zk_snark.zkp import generate_zkp, verify_zkp
import hashlib
import time
from jsonschema import validate, ValidationError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/mesh_law.log')
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
LAW_CONFIG_PATH = os.getenv('LAW_CONFIG_PATH', '/data/config/law_params.json')
AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')
SSM_PARAMETER_PATH = os.getenv('SSM_PARAMETER_PATH', '/mesh/law/config')
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
IOT_TOPIC_PREFIX = os.getenv('IOT_TOPIC_PREFIX', 'mesh')

# JSON schema for law updates
LAW_SCHEMA = {
    "type": "object",
    "properties": {
        "privacy": {"type": "string", "enum": ["strict", "moderate", "relaxed"]},
        "consent_required": {"type": "boolean"},
        "auditability": {"type": "boolean"},
        "local_micro_playbooks": {"type": "array", "items": {"type": "string"}},
        "community_rules": {"type": "array", "items": {"type": "string"}}
    }
}

class MeshLaw:
    def __init__(self, law_config_path=LAW_CONFIG_PATH):
        self.law_config_path = law_config_path
        self.laws = None
        self.lock = threading.Lock()
        self.redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
        self.ssm_client = boto3.client('ssm', region_name=AWS_REGION)
        self.iot_client = boto3.client('iot-data', region_name=AWS_REGION)
        self.load_laws()

    def load_laws(self):
        """Load laws from SSM or local JSON with caching."""
        with self.lock:
            try:
                cache_key = "mesh_laws"
                cached_laws = self.redis_client.get(cache_key)
                if cached_laws:
                    self.laws = json.loads(cached_laws)
                    logger.debug("Returning cached mesh laws")
                    return

                # Try AWS SSM Parameter Store first
                try:
                    response = self.ssm_client.get_parameter(
                        Name=SSM_PARAMETER_PATH,
                        WithDecryption=True
                    )
                    self.laws = json.loads(response['Parameter']['Value'])
                    logger.info("Loaded laws from AWS SSM Parameter Store")
                except ClientError as e:
                    logger.warning(f"SSM error, falling back to local JSON: {e}")
                    if not os.path.exists(self.law_config_path):
                        logger.info(f"Config file not found: {self.law_config_path}, using defaults")
                        self.laws = {
                            "privacy": "strict",
                            "consent_required": True,
                            "auditability": True,
                            "local_micro_playbooks": [],
                            "community_rules": []
                        }
                    else:
                        with open(self.law_config_path, 'r') as f:
                            self.laws = json.load(f)

                # Validate laws
                validate(instance=self.laws, schema=LAW_SCHEMA)
                
                # Cache laws for 300 seconds
                self.redis_client.setex(cache_key, 300, json.dumps(self.laws))
                
                # Log to QLDB
                event_data = {
                    "laws_hash": hashlib.sha3_512(cbor2.dumps(self.laws)).hexdigest(),
                    "signature": sign_message(cbor2.dumps({"laws_hash": hashlib.sha3_512(cbor2.dumps(self.laws)).hexdigest()}))
                }
                QLDBLogger.log_event("mesh_law_load", event_data)
                
                logger.info(f"Loaded mesh laws from {self.law_config_path or 'SSM'}")
            except ValidationError as e:
                logger.error(f"Invalid law configuration: {e}")
                raise
            except Exception as e:
                logger.error(f"Failed to load laws: {e}")
                raise

    def enforce(self, context, retries=3):
        """
        Enforce mesh laws based on provided context.
        Return list of compliance checks and conflicts.
        """
        with self.lock:
            if not isinstance(context, dict):
                logger.warning(f"Invalid context: {context}")
                raise ValueError("Context must be a dictionary")

            try:
                context_hash = hashlib.sha3_512(cbor2.dumps(context)).hexdigest()
                cache_key = f"law_enforce_{context_hash}"
                cached_result = self.redis_client.get(cache_key)
                if cached_result:
                    logger.debug("Returning cached enforcement result")
                    return json.loads(cached_result)

                for attempt in range(retries):
                    try:
                        if not self.laws:
                            self.load_laws()

                        compliance = []
                        conflicts = []

                        # Generate ZKP for context integrity
                        zkp = generate_zkp(context_hash)
                        if not verify_zkp(context_hash, zkp):
                            logger.warning(f"ZKP verification failed for context_hash={context_hash[:16]}...")
                            conflicts.append("Context integrity verification failed")
                            break

                        # Rule 1: Enforce privacy law
                        if self.laws.get("privacy") == "strict" and not context.get("privacy_ok", False):
                            conflicts.append("Privacy enforcement failed: strict mode requires privacy_ok=True")
                        elif self.laws.get("privacy") == "moderate" and not context.get("privacy_level", 0.0) >= 0.5:
                            conflicts.append("Privacy enforcement failed: moderate mode requires privacy_level>=0.5")

                        # Rule 2: Enforce consent
                        if self.laws.get("consent_required") and not context.get("user_consented", False):
                            conflicts.append("Missing user consent")

                        # Rule 3: Enforce auditability
                        if self.laws.get("auditability") and not context.get("audit_log", False):
                            conflicts.append("Audit log missing")

                        # Rule 4: Check local micro-playbooks
                        for playbook in self.laws.get("local_micro_playbooks", []):
                            if playbook not in context.get("executed_playbooks", []):
                                conflicts.append(f"Required micro-playbook {playbook} not executed")

                        # Rule 5: Check community rules (dynamic evaluation)
                        for rule in self.laws.get("community_rules", []):
                            # Example: rule format "key:operator:value" (e.g., "trust_score:>=:0.7")
                            try:
                                key, operator, value = rule.split(":")
                                context_value = context.get(key, None)
                                if context_value is None:
                                    conflicts.append(f"Community rule {rule} failed: missing key {key}")
                                    continue
                                value = float(value) if isinstance(context_value, (int, float)) else value
                                if operator == ">=" and not context_value >= value:
                                    conflicts.append(f"Community rule {rule} failed")
                                elif operator == "==" and not context_value == value:
                                    conflicts.append(f"Community rule {rule} failed")
                            except ValueError:
                                conflicts.append(f"Invalid community rule format: {rule}")

                        # Report compliance if no conflicts
                        if not conflicts:
                            compliance.append("All mesh laws satisfied")

                        result = (compliance, conflicts)
                        
                        # Log to QLDB
                        event_data = {
                            "context_hash": context_hash,
                            "compliance_count": len(compliance),
                            "conflict_count": len(conflicts),
                            "signature": sign_message(cbor2.dumps(result))
                        }
                        QLDBLogger.log_event("mesh_law_enforcement", event_data)

                        # Cache result for 300 seconds
                        self.redis_client.setex(cache_key, 300, json.dumps(result))
                        logger.info(f"Enforced mesh laws: {len(compliance)} compliances, {len(conflicts)} conflicts")
                        return result
                    except Exception as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for law enforcement: {e}")
                            time.sleep(2 ** attempt)  # Exponential backoff
                        else:
                            logger.error(f"Failed to enforce laws after {retries} attempts: {e}")
                            raise
            except Exception as e:
                logger.error(f"Mesh law enforcement failed: {e}")
                raise

    def sync(self, updates, retries=3):
        """
        Synchronize law changes with validation and IoT publishing.
        """
        with self.lock:
            if not isinstance(updates, dict):
                logger.warning(f"Invalid updates: {updates}")
                raise ValueError("Updates must be a dictionary")

            try:
                # Validate updates
                validate(instance=updates, schema=LAW_SCHEMA)

                for attempt in range(retries):
                    try:
                        if not self.laws:
                            self.load_laws()

                        old_laws = self.laws.copy()
                        self.laws.update(updates)

                        # Save to local JSON
                        with open(self.law_config_path, 'w') as f:
                            json.dump(self.laws, f, indent=2)

                        # Save to SSM Parameter Store
                        self.ssm_client.put_parameter(
                            Name=SSM_PARAMETER_PATH,
                            Value=json.dumps(self.laws),
                            Type='SecureString',
                            Overwrite=True
                        )

                        # Publish update to AWS IoT
                        payload = {"laws": self.laws, "updates": updates}
                        payload_bytes = cbor2.dumps(payload)
                        signature = sign_message(payload_bytes)
                        signed_payload = {'data': payload, 'signature': signature}

                        self.iot_client.publish(
                            topic=f"{IOT_TOPIC_PREFIX}/law/sync",
                            qos=1,
                            payload=cbor2.dumps(signed_payload)
                        )

                        # Log to QLDB
                        event_data = {
                            "old_laws_hash": hashlib.sha3_512(cbor2.dumps(old_laws)).hexdigest(),
                            "new_laws_hash": hashlib.sha3_512(cbor2.dumps(self.laws)).hexdigest(),
                            "signature": sign_message(cbor2.dumps(updates))
                        }
                        QLDBLogger.log_event("mesh_law_sync", event_data)

                        # Update cache
                        cache_key = "mesh_laws"
                        self.redis_client.setex(cache_key, 300, json.dumps(self.laws))
                        
                        logger.info("Synchronized mesh law updates")
                        return True
                    except ClientError as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for law sync: {e}")
                            time.sleep(2 ** attempt)  # Exponential backoff
                        else:
                            logger.error(f"Failed to sync laws after {retries} attempts: {e}")
                            raise
            except ValidationError as e:
                logger.error(f"Invalid law updates: {e}")
                raise
            except Exception as e:
                logger.error(f"Failed to sync laws: {e}")
                raise