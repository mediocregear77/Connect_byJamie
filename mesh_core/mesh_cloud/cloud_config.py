import os
import yaml
import threading
import logging
from dotenv import load_dotenv
import boto3
from botocore.exceptions import ClientError
import redis
import time
import cbor2
import hashlib
from audit_core.audit_log.qldb_logger import QLDBLogger
from security_core.pqc.dilithium import sign_message

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/cloud_config.log')
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
DEFAULT_CONFIG_PATH = os.getenv("MESH_CLOUD_CONFIG", "/etc/connection_byjamie/cloud_config.yaml")
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
SSM_PARAMETER_PATH = os.getenv("SSM_PARAMETER_PATH", "/mesh/cloud/config")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

class CloudConfig:
    def __init__(self, config_path=DEFAULT_CONFIG_PATH):
        self.config_path = config_path
        self.config = {}
        self.lock = threading.Lock()
        self.redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
        self.ssm_client = boto3.client('ssm', region_name=AWS_REGION)
        self.cache_key = "cloud_config"
        self.cache_timeout = 300  # Cache for 5 minutes
        self.cache_timestamp = 0
        self.load_config()

    def load_config(self):
        """Load config from SSM or local YAML with caching."""
        with self.lock:
            try:
                current_time = int(time.time())
                cached_config = self.redis_client.get(self.cache_key)
                if cached_config and (current_time - self.cache_timestamp) < self.cache_timeout:
                    self.config = yaml.safe_load(cached_config)
                    logger.debug("Returning cached cloud config")
                    return

                # Try AWS SSM Parameter Store first
                try:
                    response = self.ssm_client.get_parameter(
                        Name=SSM_PARAMETER_PATH,
                        WithDecryption=True
                    )
                    self.config = yaml.safe_load(response['Parameter']['Value'])
                    logger.info("Loaded config from AWS SSM Parameter Store")
                except ClientError as e:
                    logger.warning(f"SSM error, falling back to local YAML: {e}")
                    if not os.path.exists(self.config_path):
                        logger.error(f"Config file not found: {self.config_path}")
                        raise FileNotFoundError(f"Config file missing: {self.config_path}")
                    with open(self.config_path, 'r') as f:
                        self.config = yaml.safe_load(f)

                if not self.config or not isinstance(self.config, dict):
                    logger.error("Invalid or empty config")
                    raise ValueError("Invalid config file")

                # Apply environment variable overrides
                self.config['region'] = os.getenv("AWS_REGION", self.config.get('region', 'us-east-1'))
                self.config['snapshot_bucket'] = os.getenv("SNAPSHOT_BUCKET", self.config.get('snapshot_bucket', 'connection-snapshots'))
                self.config['mesh_prefix'] = os.getenv("MESH_PREFIX", self.config.get('mesh_prefix', 'mesh/'))

                # Cache config
                self.redis_client.setex(self.cache_key, self.cache_timeout, yaml.safe_dump(self.config))
                self.cache_timestamp = current_time

                # Log to QLDB
                event_data = {"config_hash": hashlib.sha3_512(cbor2.dumps(self.config)).hexdigest()}
                signature = sign_message(cbor2.dumps(event_data))
                QLDBLogger.log_event("cloud_config_load", {**event_data, "signature": signature})

                logger.info(f"Loaded cloud config from {self.config_path or 'SSM'}")
            except Exception as e:
                logger.error(f"Failed to load cloud config: {e}")
                raise

    def get(self, key, default=None):
        """Retrieve config value with validation."""
        with self.lock:
            try:
                if not self.config:
                    self.load_config()
                value = self.config.get(key, default)
                logger.debug(f"Retrieved config key={key}, value={value}")
                return value
            except Exception as e:
                logger.error(f"Failed to get config key={key}: {e}")
                return default

    def all(self):
        """Return all config values."""
        with self.lock:
            try:
                if not self.config:
                    self.load_config()
                logger.debug("Retrieved all config values")
                return self.config
            except Exception as e:
                logger.error(f"Failed to retrieve all config: {e}")
                return {}

# Example usage
if __name__ == "__main__":
    cfg = CloudConfig()
    print(cfg.all())