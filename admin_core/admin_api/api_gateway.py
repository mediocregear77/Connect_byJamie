from flask import Flask, jsonify
from flask_talisman import Talisman
import logging
from dotenv import load_dotenv
import os
from .routes import register_routes

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

def create_api_gateway():
    # Load environment variables
    load_dotenv()
    
    app = Flask(__name__)
    
    # Enforce security headers
    Talisman(app, force_https=True, strict_transport_security=True)

    try:
        register_routes(app)
        logger.info("API routes registered successfully")
    except Exception as e:
        logger.error(f"Failed to register routes: {e}")
        raise

    # Global error handlers
    @app.errorhandler(404)
    def not_found(e):
        logger.warning(f"404 error: {e}")
        return jsonify({"error": "Resource not found"}), 404

    @app.errorhandler(500)
    def internal_error(e):
        logger.error(f"500 error: {e}")
        return jsonify({"error": "Internal server error"}), 500

    return app

if __name__ == "__main__":
    app = create_api_gateway()
    host = os.getenv('API_HOST', '0.0.0.0')
    port = int(os.getenv('API_PORT', 6001))
    app.run(host=host, port=port, debug=False)