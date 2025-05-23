import os
import yaml
import logging
from dotenv import load_dotenv
import boto3
from botocore.exceptions import ClientError
import redis
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/admin_console.log')
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
CONFIG_PATH = os.getenv('ADMIN_CONSOLE_CONFIG', '/data/config/mesh_settings.yaml')
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')

# Initialize Redis client
redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)

def load_config():
    """Load admin console config from YAML with error handling."""
    try:
        if not os.path.exists(CONFIG_PATH):
            logger.error(f"Config file not found: {CONFIG_PATH}")
            raise FileNotFoundError(f"Config file missing: {CONFIG_PATH}")
        with open(CONFIG_PATH, 'r') as f:
            config = yaml.safe_load(f)
        if not config:
            logger.error("Config file is empty or invalid")
            raise ValueError("Invalid config file")
        logger.info(f"Loaded config from {CONFIG_PATH}")
        return config
    except Exception as e:
        logger.error(f"Failed to load config: {e}")
        raise

def get_dashboard_metrics():
    """Fetch live metrics from AWS services with caching."""
    cache_key = 'dashboard_metrics'
    cached_metrics = redis_client.get(cache_key)
    if cached_metrics:
        logger.debug("Returning cached dashboard metrics")
        return yaml.safe_load(cached_metrics)

    try:
        # Initialize AWS clients
        dynamodb = boto3.resource('dynamodb')
        cloudwatch = boto3.client('cloudwatch')
        kinesis = boto3.client('kinesis')

        # Fetch node counts from DynamoDB
        nodes_table = dynamodb.Table('MeshNodes')
        response = nodes_table.scan(
            Select='COUNT',
            FilterExpression='node_status = :active',
            ExpressionAttributeValues={':active': 'ACTIVE'}
        )
        active_nodes = response.get('Count', 0)
        total_nodes = nodes_table.scan(Select='COUNT').get('Count', 0)

        # Fetch beacon status from Kinesis
        beacon_stream = kinesis.describe_stream(StreamName='BeaconStream')
        beacon_shards = len(beacon_stream['StreamDescription']['Shards'])
        beacon_green = 100.0 * (active_nodes / max(total_nodes, 1))  # Percent

        # Fetch quarantined nodes from DynamoDB
        quarantine_response = nodes_table.scan(
            Select='COUNT',
            FilterExpression='node_status = :quarantined',
            ExpressionAttributeValues={':quarantined': 'QUARANTINED'}
        )
        quarantined_nodes = quarantine_response.get('Count', 0)

        # Fetch last alert from CloudWatch
        alerts = cloudwatch.get_metric_data(
            MetricDataQueries=[
                {
                    'Id': 'alerts',
                    'MetricStat': {
                        'Metric': {
                            'Namespace': 'MeshAlerts',
                            'MetricName': 'CriticalEvents',
                            'Dimensions': []
                        },
                        'Period': 300,
                        'Stat': 'Sum'
                    }
                }
            ],
            StartTime=datetime.utcnow().timestamp() - 3600,
            EndTime=datetime.utcnow().timestamp()
        )
        last_alert = "No critical events" if not alerts['MetricDataResults'][0]['Values'] else "Critical event detected"

        metrics = {
            "total_nodes": total_nodes,
            "active_nodes": active_nodes,
            "integrity_beacons_green": round(beacon_green, 1),
            "quarantined_nodes": quarantined_nodes,
            "last_alert": last_alert,
            "audit_log_url": "/admin/audit_log"
        }

        # Cache metrics for 10 seconds
        redis_client.setex(cache_key, 10, yaml.safe_dump(metrics))
        logger.info("Fetched and cached live dashboard metrics")
        return metrics

    except ClientError as e:
        logger.error(f"AWS service error: {e}")
        return {
            "total_nodes": 0,
            "active_nodes": 0,
            "integrity_beacons_green": 0.0,
            "quarantined_nodes": 0,
            "last_alert": "Service error",
            "audit_log_url": "/admin/audit_log"
        }
    except Exception as e:
        logger.error(f"Failed to fetch metrics: {e}")
        raise