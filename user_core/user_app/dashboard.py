from flask import Blueprint, render_template, redirect, url_for
from flask_login import login_required, current_user
from flask_caching import Cache
import logging
from dotenv import load_dotenv
import os
import boto3
from botocore.exceptions import ClientError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/user_app.log')
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')

dashboard_bp = Blueprint('dashboard', __name__, template_folder='templates')

# Configure caching
cache = Cache(config={'CACHE_TYPE': 'redis', 'CACHE_REDIS_URL': REDIS_URL})

def init_dashboard(app):
    cache.init_app(app)

@dashboard_bp.route('/dashboard')
@login_required
@cache.cached(timeout=15, key_prefix=lambda: f"dashboard_{current_user.id}")
def dashboard():
    try:
        username = current_user.id
        # Fetch user-specific metrics (e.g., node status, alerts)
        metrics = get_user_metrics(username)
        logger.info(f"Dashboard rendered for username={username}")
        return render_template('user_dashboard.html', user=username, metrics=metrics)
    except Exception as e:
        logger.error(f"Failed to render dashboard for username={username}: {e}")
        return render_template('error.html', error="Unable to load dashboard"), 500

def get_user_metrics(username):
    """Fetch user-specific metrics from AWS services with caching."""
    cache_key = f"user_metrics_{username}"
    cached_metrics = cache.get(cache_key)
    if cached_metrics:
        logger.debug(f"Returning cached metrics for username={username}")
        return cached_metrics

    try:
        # Initialize AWS DynamoDB client
        dynamodb = boto3.resource('dynamodb')
        user_table = dynamodb.Table('UserMetrics')

        # Fetch user-specific data (e.g., connected nodes, recent alerts)
        response = user_table.get_item(Key={'username': username})
        metrics = response.get('Item', {
            'connected_nodes': 0,
            'recent_alerts': [],
            'beacon_status': 'green'
        })

        # Cache metrics for 15 seconds
        cache.set(cache_key, metrics, timeout=15)
        logger.info(f"Fetched and cached metrics for username={username}")
        return metrics

    except ClientError as e:
        logger.error(f"AWS service error for username={username}: {e}")
        return {
            'connected_nodes': 0,
            'recent_alerts': ['Service error'],
            'beacon_status': 'unknown'
        }
    except Exception as e:
        logger.error(f"Failed to fetch metrics for username={username}: {e}")
        return {
            'connected_nodes': 0,
            'recent_alerts': ['Internal error'],
            'beacon_status': 'unknown'
        }