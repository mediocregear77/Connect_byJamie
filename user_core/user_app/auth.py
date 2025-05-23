import os
import logging
from dotenv import load_dotenv
import boto3
from botocore.exceptions import ClientError
from argon2 import PasswordHasher, exceptions
import pyotp

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
SECRETS_ARN = os.getenv('USER_CREDS_SECRET_ARN', '')

# Initialize AWS Secrets Manager client
secrets_client = boto3.client('secretsmanager')

# Initialize Argon2 password hasher
ph = PasswordHasher()

def authenticate_user(username, password, check_exists=False):
    """Validate user credentials with MFA and secure hashing."""
    if not username or (not check_exists and not password):
        logger.warning(f"Invalid input: username={username}, check_exists={check_exists}")
        return False

    try:
        # Fetch credentials from Secrets Manager
        secret_response = secrets_client.get_secret_value(SecretId=SECRETS_ARN)
        credentials = eval(secret_response['SecretString'])  # Assumes dict format {username: hashed_password}

        if check_exists:
            return username in credentials

        expected_hash = credentials.get(username)
        if not expected_hash:
            logger.warning(f"User not found: username={username}")
            return False

        # Verify password with Argon2
        try:
            ph.verify(expected_hash, password)
        except exceptions.VerifyMismatchError:
            logger.warning(f"Password mismatch for username={username}")
            return False

        # Verify TOTP (MFA)
        totp_secret = os.getenv(f'TOTP_SECRET_{username}', '')
        if not check_exists and (not totp_secret or not pyotp.TOTP(totp_secret).verify(password)):
            logger.warning(f"Invalid MFA for username={username}")
            return False

        logger.info(f"Successful authentication: username={username}")
        return True

    except ClientError as e:
        logger.error(f"Secrets Manager error: {e}")
        return False
    except Exception as e:
        logger.error(f"Authentication error for username={username}: {e}")
        return False