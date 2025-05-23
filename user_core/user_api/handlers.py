from flask import request, jsonify
from flask_login import login_required, current_user
from jsonschema import validate, ValidationError
import logging
import redis
from dotenv import load_dotenv
import os
import boto3
from botocore.exceptions import ClientError
from audit_core.audit_log.qldb_logger import QLDBLogger
from .lambda_authorizer import authorize_user
from ..user_app.dashboard import get_user_dashboard_data
from ..user_app.config import update_user_settings
from security_core.pqc.dilithium import sign_dilithium

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/user_api.log')
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
DYNAMODB_TABLE = os.getenv('DYNAMODB_TABLE', 'UserPlaybooks')

# Initialize Redis client
redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)

# JSON schemas from routes.py
from .routes import user_routes
SCHEMAS = {route['path']: route['schema'] for route in user_routes if route['schema']}

@login_required
def user_login():
    """Handle user login with MFA validation."""
    try:
        data = request.json
        validate(instance=data, schema=SCHEMAS['/api/login'])
        username = data.get('username')
        password = data.get('password')
        totp_code = data.get('totp_code')

        if authorize_user(username, password, totp_code):
            logger.info(f"Successful API login: username={username}")
            return jsonify({'status': 'success', 'message': 'Login successful'})
        else:
            logger.warning(f"Failed API login attempt: username={username}")
            return jsonify({'status': 'error', 'message': 'Invalid credentials'}), 401
    except ValidationError as e:
        logger.warning(f"Invalid login request: {e}")
        return jsonify({'status': 'error', 'message': 'Invalid request data'}), 400
    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500

@login_required
def user_logout():
    """Handle user logout."""
    try:
        username = current_user.id
        logger.info(f"Successful API logout: username={username}")
        return jsonify({'status': 'success', 'message': 'Logged out'})
    except Exception as e:
        logger.error(f"Logout error: {e}")
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500

@login_required
def get_dashboard_data():
    """Fetch user dashboard data with caching."""
    username = current_user.id
    cache_key = f"dashboard_data_{username}"
    cached_data = redis_client.get(cache_key)
    if cached_data:
        logger.debug(f"Returning cached dashboard data for username={username}")
        return jsonify({'status': 'success', 'data': eval(cached_data)})

    try:
        dashboard_data = get_user_dashboard_data(username)
        redis_client.setex(cache_key, 15, str(dashboard_data))  # Cache for 15 seconds
        logger.info(f"Fetched and cached dashboard data for username={username}")
        return jsonify({'status': 'success', 'data': dashboard_data})
    except Exception as e:
        logger.error(f"Failed to fetch dashboard data for username={username}: {e}")
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500

@login_required
def update_settings():
    """Update user settings with QLDB logging."""
    username = current_user.id
    try:
        data = request.json
        validate(instance=data, schema=SCHEMAS['/api/settings'])
        result = update_user_settings(username, data['settings'])
        
        # Log to QLDB with Dilithium signature
        event_data = {'username': username, 'settings': data['settings'], 'result': result}
        signature = sign_dilithium(str(event_data).encode())
        QLDBLogger.log_event("user_settings_update", {**event_data, 'signature': signature})
        
        logger.info(f"Settings updated for username={username}")
        return jsonify({'status': 'success', 'result': result})
    except ValidationError as e:
        logger.warning(f"Invalid settings update request for username={username}: {e}")
        return jsonify({'status': 'error', 'message': 'Invalid settings data'}), 400
    except Exception as e:
        logger.error(f"Settings update failed for username={username}: {e}")
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500

@login_required
def submit_micro_playbook():
    """Submit user-proposed micro-playbook with DynamoDB and QLDB logging."""
    username = current_user.id
    try:
        data = request.json
        validate(instance=data, schema=SCHEMAS['/api/micro_playbook'])
        playbook = data['playbook']

        # Store playbook proposal in DynamoDB
        dynamodb = boto3.resource('dynamodb')
        table = dynamodb.Table(DYNAMODB_TABLE)
        playbook_id = f"{username}_{int(datetime.now().timestamp())}"
        table.put_item(Item={
            'playbook_id': playbook_id,
            'username': username,
            'action': playbook['action'],
            'region': playbook['region'],
            'status': 'pending',
            'timestamp': datetime.now().isoformat()
        })

        # Log to QLDB with Dilithium signature
        event_data = {'username': username, 'playbook_id': playbook_id, 'playbook': playbook}
        signature = sign_dilithium(str(event_data).encode())
        QLDBLogger.log_event("user_micro_playbook", {**event_data, 'signature': signature})

        logger.info(f"Micro-playbook submitted by username={username}, playbook_id={playbook_id}")
        return jsonify({'status': 'success', 'message': 'Micro-playbook submitted', 'playbook_id': playbook_id})
    except ValidationError as e:
        logger.warning(f"Invalid micro-playbook request for username={username}: {e}")
        return jsonify({'status': 'error', 'message': 'Invalid playbook data'}), 400
    except ClientError as e:
        logger.error(f"DynamoDB error for username={username}: {e}")
        return jsonify({'status': 'error', 'message': 'Database error'}), 500
    except Exception as e:
        logger.error(f"Micro-playbook submission failed for username={username}: {e}")
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500

@login_required
def get_audit_feed():
    """Fetch public audit feed from QLDB with caching."""
    cache_key = 'audit_feed'
    cached_feed = redis_client.get(cache_key)
    if cached_feed:
        logger.debug("Returning cached audit feed")
        return jsonify({'status': 'success', 'feed': eval(cached_feed)})

    try:
        feed = QLDBLogger.get_recent_events()
        redis_client.setex(cache_key, 30, str(feed))  # Cache for 30 seconds
        logger.info("Fetched and cached audit feed")
        return jsonify({'status': 'success', 'feed': feed})
    except Exception as e:
        logger.error(f"Failed to fetch audit feed: {e}")
        return jsonify({'status': 'error', 'message': 'Internal server error', 'feed': []}), 500