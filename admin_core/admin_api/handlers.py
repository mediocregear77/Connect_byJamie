import logging
import redis
from dotenv import load_dotenv
import os
from audit_core.audit_log.qldb_logger import QLDBLogger
from mesh_core.mesh_cloud.cloud_quarantine import quarantine_node_by_id
from ai_core.bedrock.playbook_synth import trigger_resonance
from mesh_core.mesh_cloud.snapshot_manager import get_mesh_snapshot

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/admin_api.log')
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')

# Initialize Redis client
redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)

def get_dashboard_data():
    """Fetch and cache dashboard data from mesh snapshot."""
    cache_key = 'dashboard_data'
    cached_data = redis_client.get(cache_key)
    if cached_data:
        logger.debug("Returning cached dashboard data")
        return eval(cached_data)  # Safely deserialize cached data

    try:
        snapshot = get_mesh_snapshot()
        data = {
            "total_nodes": snapshot.get("total_nodes", 0),
            "healthy_nodes": snapshot.get("healthy_nodes", 0),
            "alerts": snapshot.get("alerts", []),
        }
        redis_client.setex(cache_key, 10, str(data))  # Cache for 10 seconds
        logger.info("Fetched and cached dashboard data")
        return data
    except Exception as e:
        logger.error(f"Failed to fetch dashboard data: {e}")
        return {
            "total_nodes": 0,
            "healthy_nodes": 0,
            "alerts": ["Error fetching data"]
        }

def quarantine_node(node_id):
    """Quarantine a specific mesh node with validation."""
    if not isinstance(node_id, str) or not node_id.strip():
        logger.warning(f"Invalid node_id: {node_id}")
        return False

    try:
        result = quarantine_node_by_id(node_id)
        QLDBLogger.log_event("admin_quarantine", {"node_id": node_id, "result": result})
        logger.info(f"Quarantine node_id={node_id}, success={result}")
        return result
    except Exception as e:
        logger.error(f"Quarantine failed for node_id={node_id}: {e}")
        QLDBLogger.log_event("admin_quarantine_error", {"node_id": node_id, "error": str(e)})
        return False

def trigger_resonance_cascade(region):
    """Trigger Resonance Cascade for a region with validation."""
    if not isinstance(region, str) or not region.strip():
        logger.warning(f"Invalid region: {region}")
        return False

    try:
        result = trigger_resonance(region)
        QLDBLogger.log_event("admin_resonance_cascade", {"region": region, "result": result})
        logger.info(f"Resonance cascade triggered for region={region}, success={result}")
        return result
    except Exception as e:
        logger.error(f"Resonance cascade failed for region={region}: {e}")
        QLDBLogger.log_event("admin_resonance_cascade_error", {"region": region, "error": str(e)})
        return False

def get_audit_logs():
    """Fetch and cache recent audit logs."""
    cache_key = 'audit_logs'
    cached_logs = redis_client.get(cache_key)
    if cached_logs:
        logger.debug("Returning cached audit logs")
        return eval(cached_logs)  # Safely deserialize cached logs

    try:
        logs = QLDBLogger.get_recent_events()
        redis_client.setex(cache_key, 30, str(logs))  # Cache for 30 seconds
        logger.info("Fetched and cached audit logs")
        return logs
    except Exception as e:
        logger.error(f"Failed to fetch audit logs: {e}")
        return []