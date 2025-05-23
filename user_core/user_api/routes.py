import logging
from .handlers import (
    user_login,
    user_logout,
    get_dashboard_data,
    update_settings,
    submit_micro_playbook,
    get_audit_feed
)

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

# Define user routes with metadata for rate limiting and validation
user_routes = [
    {
        'path': '/api/login',
        'view_func': user_login,
        'methods': ['POST'],
        'description': 'User login with credentials and MFA',
        'rate_limit': '10 per minute',
        'schema': {
            'type': 'object',
            'properties': {
                'username': {'type': 'string', 'minLength': 1},
                'password': {'type': 'string', 'minLength': 1},
                'totp_code': {'type': 'string', 'minLength': 6, 'maxLength': 6}
            },
            'required': ['username', 'password', 'totp_code']
        }
    },
    {
        'path': '/api/logout',
        'view_func': user_logout,
        'methods': ['POST'],
        'description': 'User logout',
        'rate_limit': '10 per minute',
        'schema': None
    },
    {
        'path': '/api/dashboard',
        'view_func': get_dashboard_data,
        'methods': ['GET'],
        'description': 'Fetch user dashboard metrics',
        'rate_limit': '50 per minute',
        'schema': None
    },
    {
        'path': '/api/settings',
        'view_func': update_settings,
        'methods': ['POST'],
        'description': 'Update user settings',
        'rate_limit': '20 per minute',
        'schema': {
            'type': 'object',
            'properties': {
                'settings': {'type': 'object'}
            },
            'required': ['settings']
        }
    },
    {
        'path': '/api/micro_playbook',
        'view_func': submit_micro_playbook,
        'methods': ['POST'],
        'description': 'Submit user-proposed micro-playbook',
        'rate_limit': '5 per minute',
        'schema': {
            'type': 'object',
            'properties': {
                'playbook': {'type': 'object', 'properties': {
                    'action': {'type': 'string', 'minLength': 1},
                    'region': {'type': 'string', 'minLength': 1}
                }, 'required': ['action', 'region']}
            },
            'required': ['playbook']
        }
    },
    {
        'path': '/api/audit_feed',
        'view_func': get_audit_feed,
        'methods': ['GET'],
        'description': 'Fetch public audit feed',
        'rate_limit': '30 per minute',
        'schema': None
    }
]

# Register routes with logging
def register_routes(app):
    """Register user API routes with the Flask app."""
    try:
        for route in user_routes:
            app.add_url_rule(
                route['path'],
                view_func=route['view_func'],
                methods=route['methods']
            )
            logger.info(f"Registered user API route: {route['path']} with methods {route['methods']}")
    except Exception as e:
        logger.error(f"Failed to register user API routes: {e}")
        raise