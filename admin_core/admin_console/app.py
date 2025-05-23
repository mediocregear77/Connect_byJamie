from flask import Flask, redirect, url_for
from flask_talisman import Talisman
import logging
from dotenv import load_dotenv
import os
from admin_console.config import Config
from admin_console.auth import auth_blueprint
from admin_console.dashboard import dashboard_blueprint

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

def create_app():
    # Load environment variables
    load_dotenv()
    
    app = Flask(__name__, static_folder="static")
    app.config.from_object(Config)

    # Enforce security headers
    Talisman(app, force_https=True, strict_transport_security=True)

    # Register blueprints dynamically
    blueprints = [
        (auth_blueprint, '/auth'),
        (dashboard_blueprint, '/dashboard')
    ]
    for blueprint, prefix in blueprints:
        try:
            app.register_blueprint(blueprint, url_prefix=prefix)
            logger.info(f"Registered blueprint {blueprint.name} at {prefix}")
        except Exception as e:
            logger.error(f"Failed to register blueprint {blueprint.name}: {e}")
            raise

    @app.route('/')
    def index():
        try:
            return redirect(url_for('dashboard.index'))
        except Exception as e:
            logger.error(f"Redirect failed: {e}")
            return {"error": "Internal server error"}, 500

    @app.errorhandler(404)
    def not_found(e):
        logger.warning(f"404 error: {e}")
        return {"error": "Resource not found"}, 404

    return app

if __name__ == "__main__":
    app = create_app()
    host = os.getenv('FLASK_HOST', '0.0.0.0')
    port = int(os.getenv('FLASK_PORT', 8080))
    app.run(host=host, port=port, debug=False)