from flask import Blueprint, request, jsonify
from flask_login import login_required
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
from dotenv import load_dotenv
from jsonschema import validate, ValidationError
from .routes import user_routes
from .handlers import handle_api_request

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

api_gateway = Blueprint('user_api_gateway', __name__)

# Configure rate limiter
limiter = Limiter(key_func=get_remote_address)

# JSON schema for generic API validation
GENERIC_API_SCHEMA = {
    "type": "object",
    "properties": {
        "path": {"type": "string", "minLength": 1},
        "data": {"type": ["object", "null"]}
    },
    "required": ["path"]
}

def init_api_gateway(app):
    """Initialize the API gateway with the Flask app."""
    limiter.init_app(app)
    try:
        # Register routes from user_routes
        for route, view_func, methods in user_routes:
            api_gateway.add_url_rule(
                route,
                view_func=login_required(view_func),  # Secure routes with authentication
                methods=methods
            )
            logger.info(f"Registered user API route: {route} with methods {methods}")
    except Exception as e:
        logger.error(f"Failed to register user API routes: {e}")
        raise

# Catch-all route for custom logic
@api_gateway.route('/api/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
@login_required
@limiter.limit("50 per minute")
def generic_api(path):
    try:
        # Validate request data
        request_data = {"path": path, "data": request.json} if request.is_json else {"path": path, "data": None}
        validate(instance=request_data, schema=GENERIC_API_SCHEMA)
        
        response = handle_api_request(request)
        logger.info(f"Handled API request for path={path}, method={request.method}")
        return jsonify(response)
    except ValidationError as e:
        logger.warning(f"Invalid API request for path={path}: {e}")
        return jsonify({"error": "Invalid request data"}), 400
    except Exception as e:
        logger.error(f"Failed to handle API request for path={path}: {e}")
        return jsonify({"error": "Internal server error"}), 500