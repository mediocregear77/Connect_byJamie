import os
import logging
from dotenv import load_dotenv
import boto3
from botocore.exceptions import ClientError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import kyber
from cryptography.hazmat.backends import default_backend

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/admin_secrets.log')
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
KMS_KEY_ID = os.getenv('KMS_KEY_ID', '')
CREDS_PATH = os.getenv('ADMIN_CREDS_PATH', '/app/admin_core/admin_secrets/admin_creds.enc')

def get_admin_creds():
    """Decrypt and return admin credentials using AWS KMS and Kyber."""
    try:
        if not os.path.exists(CREDS_PATH):
            logger.error(f"Credentials file not found: {CREDS_PATH}")
            raise FileNotFoundError(f"Credentials file missing: {CREDS_PATH}")

        # Initialize KMS client
        kms_client = boto3.client('kms')

        # Read encrypted credentials
        with open(CREDS_PATH, 'rb') as f:
            encrypted_creds = f.read()

        # Decrypt using KMS (Kyber-based key)
        decrypted_response = kms_client.decrypt(
            CiphertextBlob=encrypted_creds,
            KeyId=KMS_KEY_ID,
            EncryptionAlgorithm='SYMMETRIC_DEFAULT'
        )
        decrypted_data = decrypted_response['Plaintext'].decode('utf-8')

        # Parse credentials (expected format: username:password)
        username, password = decrypted_data.split(':', 1)
        if not username or not password:
            logger.error("Invalid credentials format")
            raise ValueError("Invalid credentials format")

        logger.info("Admin credentials decrypted successfully")
        return username, password

    except ClientError as e:
        logger.error(f"KMS decryption error: {e}")
        raise
    except Exception as e:
        logger.error(f"Failed to load admin credentials: {e}")
        raise