import hashlib
import os
import logging
import threading
from dotenv import load_dotenv
import boto3
from botocore.exceptions import ClientError
import redis
import cbor2
from audit_core.audit_log.qldb_logger import QLDBLogger
from security_core.pqc.dilithium import sign_message
from security_core.zk_snark.zkp import generate_zkp, verify_zkp

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/model_attestation.log')
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
MODEL_WEIGHTS_PATH = os.getenv("MODEL_WEIGHTS_PATH", "/opt/model_weights/seed_weights.enc")
SECRETS_ARN = os.getenv("MODEL_HASH_SECRETS_ARN", "")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")

class ModelAttestation:
    def __init__(self):
        self.lock = threading.Lock()
        self.redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
        self.secrets_client = boto3.client('secretsmanager', region_name=AWS_REGION)
        self.trusted_hashes = None
        self.cache_key = "trusted_model_hashes"
        self.cache_timeout = 3600  # Cache for 1 hour

    def _load_trusted_hashes(self):
        """Load trusted model hashes from AWS Secrets Manager with caching."""
        with self.lock:
            try:
                cached_hashes = self.redis_client.get(self.cache_key)
                if cached_hashes:
                    self.trusted_hashes = json.loads(cached_hashes)
                    logger.debug("Returning cached trusted model hashes")
                    return

                # Fetch from Secrets Manager
                response = self.secrets_client.get_secret_value(SecretId=SECRETS_ARN)
                self.trusted_hashes = json.loads(response['SecretString'])['hashes']
                
                # Cache hashes
                self.redis_client.setex(self.cache_key, self.cache_timeout, json.dumps(self.trusted_hashes))
                
                # Log to QLDB
                event_data = {"hash_count": len(self.trusted_hashes)}
                signature = sign_message(cbor2.dumps(event_data))
                QLDBLogger.log_event("trusted_hashes_load", {**event_data, "signature": signature})
                
                logger.info("Loaded trusted model hashes from Secrets Manager")
            except ClientError as e:
                logger.error(f"Secrets Manager error: {e}")
                raise
            except Exception as e:
                logger.error(f"Failed to load trusted hashes: {e}")
                raise

    def verify_model_integrity(self, model_hash: str) -> bool:
        """Verify model hash with ZKP and QLDB logging."""
        with self.lock:
            if not isinstance(model_hash, str) or len(model_hash) != 128:  # SHA3-512 hex length
                logger.warning(f"Invalid model hash: {model_hash}")
                return False

            try:
                if not self.trusted_hashes:
                    self._load_trusted_hashes()

                # Generate and verify ZKP
                zkp = generate_zkp(model_hash)
                if not verify_zkp(model_hash, zkp):
                    logger.warning(f"ZKP verification failed for model_hash={model_hash[:16]}...")
                    return False

                is_valid = model_hash in self.trusted_hashes
                cache_key = f"model_integrity_{model_hash}"
                
                # Cache result for 300 seconds
                self.redis_client.setex(cache_key, 300, json.dumps(is_valid))
                
                # Log to QLDB
                event_data = {
                    "model_hash": model_hash,
                    "is_valid": is_valid,
                    "signature": sign_message(cbor2.dumps({"model_hash": model_hash}))
                }
                QLDBLogger.log_event("model_integrity_check", event_data)

                if not is_valid:
                    logger.warning(f"Model attestation failed for hash: {model_hash[:16]}...")
                else:
                    logger.info(f"Model attestation succeeded for hash: {model_hash[:16]}...")
                return is_valid
            except Exception as e:
                logger.error(f"Failed to verify model integrity: {e}")
                return False

    def generate_model_hash(self, model_weights_path: str = MODEL_WEIGHTS_PATH) -> str:
        """Compute SHA3-512 hash of encrypted model weights with validation."""
        with self.lock:
            if not isinstance(model_weights_path, str) or not model_weights_path.strip():
                logger.warning(f"Invalid model weights path: {model_weights_path}")
                raise ValueError("Invalid model weights path")

            try:
                if not os.path.exists(model_weights_path):
                    logger.error(f"No model weights at {model_weights_path}")
                    raise FileNotFoundError(f"No model weights at {model_weights_path}")

                cache_key = f"model_hash_{model_weights_path}"
                cached_hash = self.redis_client.get(cache_key)
                if cached_hash:
                    logger.debug(f"Returning cached model hash for {model_weights_path}")
                    return cached_hash

                with open(model_weights_path, "rb") as f:
                    raw = f.read()
                model_hash = hashlib.sha3_512(raw).hexdigest()

                # Cache hash for 3600 seconds
                self.redis_client.setex(cache_key, 3600, model_hash)
                
                # Log to QLDB
                event_data = {
                    "model_weights_path": model_weights_path,
                    "model_hash": model_hash,
                    "signature": sign_message(cbor2.dumps({"model_hash": model_hash}))
                }
                QLDBLogger.log_event("model_hash_generate", event_data)

                logger.info(f"Generated model hash for {model_weights_path}: {model_hash[:16]}...")
                return model_hash
            except Exception as e:
                logger.error(f"Failed to generate model hash: {e}")
                raise

# Example usage
if __name__ == "__main__":
    attestation = ModelAttestation()
    model_hash = attestation.generate_model_hash()
    is_valid = attestation.verify_model_integrity(model_hash)
    print(f"Model attestation: {'Valid' if is_valid else 'Invalid'}")