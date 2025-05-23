import yaml
import os
import threading
import logging
from dotenv import load_dotenv
import boto3
from botocore.exceptions import ClientError
import time
from audit_core.audit_log.qldb_logger import QLDBLogger
from security_core.pqc.dilithium import sign_message
import cbor2

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/mesh_node_config.log')
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
CONFIG_PATH = os.getenv('MESH_NODE_CONFIG', '/data/config/mesh_settings.yaml')
AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')
SSM_PARAMETER_PATH = os.getenv('SSM_PARAMETER_PATH', '/mesh/node/config')

class MeshNodeConfig:
    def __init__(self, config_path=CONFIG_PATH):
        self.config_path = config_path
        self.lock = threading.Lock()
        self.config = None
        self.cache_timestamp = 0
        self.cache_timeout = 300  # Cache for 5 minutes
        self.ssm_client = boto3.client('ssm', region_name=AWS_REGION)
        self.load_config()

    def load_config(self):
        """Load config from SSM Parameter Store or local YAML with caching."""
        with self.lock:
            try:
                current_time = int(time.time())
                if self.config and (current_time - self.cache_timestamp) < self.cache_timeout:
                    logger.debug("Returning cached config")
                    return self.config

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

                self.cache_timestamp = current_time
                logger.info(f"Loaded config from {self.config_path or 'SSM'}")
                
                # Log config load to QLDB
                event_data = {"node_id": self.get('node_id', 'unknown'), "config_hash": self._hash_config()}
                signature = sign_message(cbor2.dumps(event_data))
                QLDBLogger.log_event("config_load", {**event_data, "signature": signature})
                
                return self.config
            except Exception as e:
                logger.error(f"Failed to load config: {e}")
                raise

    def _hash_config(self):
        """Calculate SHA3-512 hash of config for integrity."""
        try:
            return hashlib.sha3_512(cbor2.dumps(self.config, sort_keys=True)).hexdigest()
        except Exception as e:
            logger.error(f"Failed to hash config: {e}")
            return None

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

    def save(self):
        """Save config to local YAML and SSM with QLDB logging."""
        with self.lock:
            try:
                # Save to local YAML
                with open(self.config_path, 'w') as f:
                    yaml.safe_dump(self.config, f)
                
                # Save to SSM Parameter Store
                self.ssm_client.put_parameter(
                    Name=SSM_PARAMETER_PATH,
                    Value=yaml.safe_dump(self.config),
                    Type='SecureString',
                    Overwrite=True
                )
                
                # Log to QLDB
                event_data = {"node_id": self.get('node_id', 'unknown'), "config_hash": self._hash_config()}
                signature = sign_message(cbor2.dumps(event_data))
                QLDBLogger.log_event("config_save", {**event_data, "signature": signature})
                
                self.cache_timestamp = int(time.time())
                logger.info(f"Configuration saved to {self.config_path} and SSM")
            except ClientError as e:
                logger.error(f"SSM save error: {e}")
                raise
            except Exception as e:
                logger.error(f"Failed to save config: {e}")
                raise

    def set(self, key, value):
        """Set config value and save with QLDB logging."""
        with self.lock:
            try:
                if not self.config:
                    self.load_config()
                old_value = self.config.get(key)
                self.config[key] = value
                
                # Log to QLDB
                event_data = {
                    "node_id": self.get('node_id', 'unknown'),
                    "key": key,
                    "old_value": old_value,
                    "new_value": value,
                    "config_hash": self._hash_config()
                }
                signature = sign_message(cbor2.dumps(event_data))
                QLDBLogger.log_event("config_update", {**event_data, "signature": signature})
                
                self.save()
                logger.info(f"Set config key={key}, value={value}")
            except Exception as e:
                logger.error(f"Failed to set config key={key}: {e}")
                raise