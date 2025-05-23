import os
import json
import threading
import logging
from dotenv import load_dotenv
import boto3
from botocore.exceptions import ClientError
import redis
from audit_core.audit_log.qldb_logger import QLDBLogger
from security_core.pqc.dilithium import sign_message
import cbor2

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/greengrass_init.log')
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
CONFIG_PATH = os.getenv('MESH_CONFIG_PATH', '/etc/mesh_config.json')
AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')
SSM_PARAMETER_PATH = os.getenv('SSM_PARAMETER_PATH', '/mesh/cloud/config')
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')

# Initialize Redis client
redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)

class GreengrassInitializer:
    def __init__(self):
        self.lock = threading.Lock()
        self.client = boto3.client('greengrassv2', region_name=AWS_REGION)
        self.ssm_client = boto3.client('ssm', region_name=AWS_REGION)
        self.config_cache_key = 'greengrass_config'
        self.cache_timeout = 300  # Cache for 5 minutes

    def load_config(self):
        """Load config from SSM or local JSON with caching."""
        with self.lock:
            try:
                cached_config = redis_client.get(self.config_cache_key)
                if cached_config:
                    logger.debug("Returning cached Greengrass config")
                    return json.loads(cached_config)

                # Try AWS SSM Parameter Store first
                try:
                    response = self.ssm_client.get_parameter(
                        Name=SSM_PARAMETER_PATH,
                        WithDecryption=True
                    )
                    config = json.loads(response['Parameter']['Value'])
                    logger.info("Loaded config from AWS SSM Parameter Store")
                except ClientError as e:
                    logger.warning(f"SSM error, falling back to local JSON: {e}")
                    if not os.path.exists(CONFIG_PATH):
                        logger.error(f"Config file not found: {CONFIG_PATH}")
                        raise FileNotFoundError(f"Config file missing: {CONFIG_PATH}")
                    with open(CONFIG_PATH, 'r') as f:
                        config = json.load(f)

                if not config or not isinstance(config, dict):
                    logger.error("Invalid or empty config")
                    raise ValueError("Invalid config file")

                # Cache config
                redis_client.setex(self.config_cache_key, self.cache_timeout, json.dumps(config))
                
                # Log to QLDB
                event_data = {"config_hash": hashlib.sha3_512(cbor2.dumps(config)).hexdigest()}
                signature = sign_message(cbor2.dumps(event_data))
                QLDBLogger.log_event("greengrass_config_load", {**event_data, "signature": signature})
                
                logger.info(f"Loaded config from {CONFIG_PATH or 'SSM'}")
                return config
            except Exception as e:
                logger.error(f"Failed to load config: {e}")
                raise

    def initialize_greengrass(self):
        """Initialize Greengrass component with QLDB logging."""
        with self.lock:
            try:
                config = self.load_config()
                thing_name = config.get("thing_name", "mesh_node_default")
                mesh_group = config.get("mesh_group", "default")

                # Create Greengrass component version
                recipe = {
                    "thingName": thing_name,
                    "meshGroup": mesh_group,
                    "version": "1.0.0",
                    "configuration": config.get("configuration", {})
                }
                response = self.client.create_component_version(
                    inlineRecipe=json.dumps(recipe)
                )
                
                # Log to QLDB
                event_data = {
                    "thing_name": thing_name,
                    "mesh_group": mesh_group,
                    "component_arn": response.get('arn', 'unknown')
                }
                signature = sign_message(cbor2.dumps(event_data))
                QLDBLogger.log_event("greengrass_init", {**event_data, "signature": signature})
                
                logger.info(f"Greengrass component initialized for {thing_name}: {response}")
                return True
            except ClientError as e:
                logger.error(f"Greengrass initialization error: {e}")
                return False
            except Exception as e:
                logger.error(f"Failed to initialize Greengrass: {e}")
                return False

# Singleton instance
initializer = GreengrassInitializer()

def initialize_greengrass():
    """Entry point for Greengrass initialization."""
    return initializer.initialize_greengrass()

if __name__ == "__main__":
    initialize_greengrass()