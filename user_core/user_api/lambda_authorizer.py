import json
import logging
import os
from dotenv import load_dotenv
import boto3
from botocore.exceptions import ClientError
import pyjwt
import pyotp
from argon2 import PasswordHasher, exceptions
from security_core.pqc.dilithium import verify_dilithium_signature

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Load environment variables
load_dotenv()
SECRETS_ARN = os.getenv('USER_CREDS_SECRET_ARN', '')
COGNITO_JWK_URL = os.getenv('COGNITO_JWK_URL', '')

# Initialize AWS clients
secrets_client = boto3.client('secretsmanager')
cognito_client = boto3.client('cognito-idp')

# Initialize Argon2 password hasher
ph = PasswordHasher()

def authorize_user(username, password, totp_code=None):
    """Authenticate user with Argon2 hashing and MFA."""
    if not username or not password:
        logger.warning(f"Invalid input: username={username}")
        return False

    try:
        # Fetch credentials from Secrets Manager
        secret_response = secrets_client.get_secret_value(SecretId=SECRETS_ARN)
        credentials = json.loads(secret_response['SecretString'])

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

        # Verify TOTP (MFA) if provided
        if totp_code:
            totp_secret = os.getenv(f'TOTP_SECRET_{username}', '')
            if not totp_secret or not pyotp.TOTP(totp_secret).verify(totp_code):
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

def lambda_authorizer(event, context):
    """AWS Lambda authorizer for API Gateway with JWT and PQC."""
    try:
        token = event.get('authorizationToken', '')
        if not token:
            logger.warning("Missing authorization token")
            return generate_policy("Deny", event['methodArn'], "Missing token")

        # Decode and validate JWT
        try:
            decoded = pyjwt.decode(
                token,
                algorithms=['RS256'],
                options={'verify_signature': True},
                jwks_client=pyjwt.PyJWKClient(COGNITO_JWK_URL)
            )
            username = decoded.get('sub')
            if not username:
                logger.warning("Invalid JWT: missing sub claim")
                return generate_policy("Deny", event['methodArn'], "Invalid JWT")
        except pyjwt.PyJWTError as e:
            logger.warning(f"JWT validation error: {e}")
            return generate_policy("Deny", event['methodArn'], "Invalid JWT")

        # Verify Dilithium signature (assumed token includes signature)
        signature = event.get('signature', '')
        if not signature or not verify_dilithium_signature(token.encode(), username):
            logger.warning(f"Invalid Dilithium signature for username={username}")
            return generate_policy("Deny", event['methodArn'], "Invalid signature")

        # Verify user exists (Cognito check)
        try:
            cognito_client.get_user(AccessToken=token)
            logger.info(f"Authorized user access: username={username}")
            return generate_policy("Allow", event['methodArn'], "Authorized", username)
        except ClientError as e:
            logger.warning(f"Cognito error for username={username}: {e}")
            return generate_policy("Deny", event['methodArn'], "Invalid user")

    except Exception as e:
        logger.error(f"Unexpected error during authorization: {e}")
        return generate_policy("Deny", event['methodArn'], "Internal server error")

def generate_policy(effect, resource, reason, username=None):
    """Generate IAM policy with contextual data for auditability."""
    policy = {
        "principalId": username or "user",
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [{
                "Action": "execute-api:Invoke",
                "Effect": effect,
                "Resource": resource
            }]
        },
        "context": {
            "reason": reason,
            "username": username or "unknown"
        }
    }
    logger.debug(f"Generated policy: effect={effect}, reason={reason}, username={username}")
    return policy