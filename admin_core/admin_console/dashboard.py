from flask import Blueprint, render_template, redirect, url_for
from flask_login import login_required
from flask_caching import Cache
import logging
from admin_console.config import get_dashboard_metrics

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

dashboard_blueprint = Blueprint('dashboard', __name__, template_folder='templates')

# Configure caching
cache = Cache(config={'CACHE_TYPE': 'redis', 'CACHE_REDIS_URL': 'redis://localhost:6379/0'})

def init_dashboard(app):
    cache.init_app(app)

@dashboard_blueprint.route('/')
@login_required
@cache.cached(timeout=10)  # Cache metrics for 10 seconds
def index():
    try:
        # Pull live system metrics, beacon status, and alerts
        metrics = get_dashboard_metrics()
        logger.info("Dashboard metrics retrieved successfully")
        return render_template('dashboard.html', metrics=metrics)
    except Exception as e:
        logger.error(f"Failed to load dashboard metrics: {e}")
        return render_template('error.html', error="Unable to load dashboard"), 500

# The dashboard displays: system health, active nodes, beacon status, alerts, audit log links, and admin controls.