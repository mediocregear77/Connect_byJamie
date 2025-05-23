import base64
import json
import logging
import os
import pyotp
from botocore.exceptions import ClientError
from security_core.pqc.dilithium import verify_dilithium_signature
from admin_core.admin_secrets.load_creds import get_admin_creds

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    """AWS Lambda authorizer for admin API endpoints with MFA and PQC."""
    try:
        token = event.get('authorizationToken', '')
        if not token:
            logger.warning("Missing authorization token")
            return generate_policy("Deny", event['methodArn'], "Missing token")

        # Parse token
        scheme, encoded = token.split()
        if scheme.lower() != "basic":
            logger.warning(f"Invalid scheme: {scheme}")
            return generate_policy("Deny", event['methodArn'], "Invalid scheme")

        # Decode and validate credentials
        decoded = base64.b64decode(encoded).decode('utf-8')
        username, password, totp_code = decoded.split(":", 2)  # Expect username:password:totp_code

        # Verify Dilithium signature (assumed token includes signature)
        if not verify_dilithium_signature(encoded.encode(), username):
            logger.warning(f"Invalid Dilithium signature for username={username}")
            return generate_policy("Deny", event['methodArn'], "Invalid signature")

        # Check admin credentials
        admin_user, admin_pass = get_admin_creds()
        if username != admin_user or password != admin_pass:
            logger.warning(f"Invalid credentials for username={username}")
            return generate_policy("Deny", event['methodArn'], "Invalid credentials")

        # Verify TOTP (MFA)
        totp_secret = os.getenv(f'TOTP_SECRET_{username}', '')
        if not totp_secret or not pyotp.TOTP(totp_secret).verify(totp_code):
            logger.warning(f"Invalid MFA code for username={username}")
            return generate_policy("Deny", event['methodArn'], "Invalid MFA code")

        logger.info(f"Authorized admin access for username={username}")
        return generate_policy("Allow", event['methodArn'], "Authorized", username)

    except (ValueError, ClientError) as e:
        logger.error(f"Authorization error: {e}")
        return generate_policy("Deny", event['methodArn'], f"Authorization error: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error during authorization: {e}")
        return generate_policy("Deny", event['methodArn'], "Internal server error")

def generate_policy(effect, resource, reason, username=None):
    """Generate IAM policy with contextual data for auditability."""
    policy = {
        "principalId": username or "admin",
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