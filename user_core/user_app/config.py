import os
import logging
from dotenv import load_dotenv

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

class UserAppConfig:
    """Configuration for the user app with secure environment variable loading."""
    
    def __init__(self):
        try:
            self.SECRET_KEY = self._get_required_env('USER_APP_SECRET_KEY')
            self.SESSION_COOKIE_NAME = 'user_session'
            self.SESSION_COOKIE_SECURE = True  # Enforce HTTPS for cookies
            self.SESSION_COOKIE_HTTPONLY = True  # Prevent JS access
            self.SESSION_COOKIE_SAMESITE = 'Lax'  # CSRF protection
            self.STATIC_FOLDER = 'static'
            self.TEMPLATE_FOLDER = 'templates'
            self.REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
            self.AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')
            self.USER_CREDS_SECRET_ARN = os.getenv('USER_CREDS_SECRET_ARN', '')
            self.DYNAMODB_TABLE = os.getenv('DYNAMODB_TABLE', 'UserMetrics')
            logger.info("User app configuration loaded successfully")
        except ValueError as e:
            logger.error(f"Configuration error: {e}")
            raise

    def _get_required_env(self, key):
        """Fetch required environment variable or raise error."""
        value = os.getenv(key)
        if not value:
            raise ValueError(f"Missing required environment variable: {key}")
        return value

config = UserAppConfig()

# Export for backward compatibility
USER_APP_SECRET_KEY = config.SECRET_KEY