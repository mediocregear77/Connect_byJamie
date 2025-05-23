from flask import request, jsonify
from flask_login import login_required
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
from jsonschema import validate, ValidationError
from .handlers import (
    get_dashboard_data,
    quarantine_node,
    trigger_resonance_cascade,
    get_audit_logs,
)

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

# Configure rate limiter
limiter = Limiter(key_func=get_remote_address)

# JSON schemas for validation
QUARANTINE_SCHEMA = {
    "type": "object",
    "properties": {"node_id": {"type": "string", "minLength": 1}},
    "required": ["node_id"],
}
RESONANCE_SCHEMA = {
    "type": "object",
    "properties": {"region": {"type": "string", "minLength": 1}},
    "required": ["region"],
}

def register_routes(app):
    # Initialize limiter with app
    limiter.init_app(app)

    @app.route("/api/admin/dashboard", methods=["GET"])
    @login_required
    @limiter.limit("100 per minute")
    def dashboard():
        try:
            data = get_dashboard_data()
            logger.info("Dashboard data retrieved successfully")
            return jsonify(data)
        except Exception as e:
            logger.error(f"Failed to fetch dashboard data: {e}")
            return jsonify({"error": "Internal server error"}), 500

    @app.route("/api/admin/quarantine", methods=["POST"])
    @login_required
    @limiter.limit("10 per minute")
    def quarantine():
        try:
            validate(instance=request.json, schema=QUARANTINE_SCHEMA)
            node_id = request.json.get("node_id")
            result = quarantine_node(node_id)
            logger.info(f"Quarantine requested for node_id={node_id}, success={result}")
            return jsonify({"success": result})
        except ValidationError as e:
            logger.warning(f"Invalid quarantine request: {e}")
            return jsonify({"error": "Invalid node_id"}), 400
        except Exception as e:
            logger.error(f"Quarantine failed: {e}")
            return jsonify({"error": "Internal server error"}), 500

    @app.route("/api/admin/resonance_cascade", methods=["POST"])
    @login_required
    @limiter.limit("5 per minute")
    def resonance_cascade():
        try:
            validate(instance=request.json, schema=RESONANCE_SCHEMA)
            region = request.json.get("region")
            result = trigger_resonance_cascade(region)
            logger.info(f"Resonance cascade triggered for region={region}, success={result}")
            return jsonify({"success": result})
        except ValidationError as e:
            logger.warning(f"Invalid resonance cascade request: {e}")
            return jsonify({"error": "Invalid region"}), 400
        except Exception as e:
            logger.error(f"Resonance cascade failed: {e}")
            return jsonify({"error": "Internal server error"}), 500

    @app.route("/api/admin/audit_logs", methods=["GET"])
    @login_required
    @limiter.limit("50 per minute")
    def audit_logs():
        try:
            logs = get_audit_logs()
            logger.info("Audit logs retrieved successfully")
            return jsonify({"logs": logs})
        except Exception as e:
            logger.error(f"Failed to fetch audit logs: {e}")
            return jsonify({"error": "Internal server error"}), 500