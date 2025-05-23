import os
import base64
import logging
import threading
from dotenv import load_dotenv
import redis
import cbor2
import boto3
from botocore.exceptions import ClientError
from audit_core.audit_log.qldb_logger import QLDBLogger
import hashlib
import time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dilithium
from cryptography.hazmat.backends import default_backend

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/dilithium.log')
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
KMS_KEY_ID = os.getenv('KMS_KEY_ID', '')
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')
IOT_TOPIC_PREFIX = os.getenv('IOT_TOPIC_PREFIX', 'mesh')

class DilithiumSigner:
    """
    Dilithium PQC Digital Signature interface using pycryptodome.
    Supports keygen, sign, verify with quantum-secure integration.
    """

    def __init__(self):
        self.lock = threading.Lock()
        self.redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
        self.kms_client = boto3.client('kms', region_name=AWS_REGION)
        self.iot_client = boto3.client('iot-data', region_name=AWS_REGION)

    def keygen(self, retries=3):
        """Generate a Dilithium keypair with KMS storage and QLDB logging."""
        with self.lock:
            try:
                cache_key = "dilithium_keypair"
                cached_keypair = self.redis_client.get(cache_key)
                if cached_keypair:
                    pub, sec = json.loads(cached_keypair)
                    logger.debug("Returning cached Dilithium keypair")
                    return pub, sec

                for attempt in range(retries):
                    try:
                        # Generate Dilithium keypair using pycryptodome
                        private_key = dilithium.Dilithium512.generate_private_key(backend=default_backend())
                        public_key = private_key.public_key()

                        # Serialize keys
                        pub_bytes = public_key.public_bytes(
                            encoding=serialization.Encoding.Raw,
                            format=serialization.PublicFormat.Raw
                        )
                        sec_bytes = private_key.private_bytes(
                            encoding=serialization.Encoding.Raw,
                            format=serialization.PrivateFormat.Raw
                        )

                        pub = base64.b64encode(pub_bytes).decode()
                        sec = base64.b64encode(sec_bytes).decode()

                        # Generate ZKP for keypair integrity
                        keypair_hash = hashlib.sha3_512(cbor2.dumps([pub, sec])).hexdigest()
                        zkp = generate_zkp(keypair_hash)
                        if not verify_zkp(keypair_hash, zkp):
                            logger.warning(f"ZKP verification failed for keypair")
                            raise RuntimeError("Keypair integrity verification failed")

                        # Store private key in KMS
                        response = self.kms_client.encrypt(
                            KeyId=KMS_KEY_ID,
                            Plaintext=sec_bytes,
                            EncryptionAlgorithm='SYMMETRIC_DEFAULT'
                        )
                        encrypted_sec = base64.b64encode(response['CiphertextBlob']).decode()

                        # Log to QLDB
                        event_data = {
                            "keypair_hash": keypair_hash,
                            "public_key": pub[:16],
                            "signature": sign_message(cbor2.dumps({"keypair_hash": keypair_hash}))
                        }
                        QLDBLogger.log_event("dilithium_keygen", event_data)

                        # Cache keypair for 3600 seconds
                        self.redis_client.setex(cache_key, 3600, json.dumps((pub, encrypted_sec)))

                        # Publish to AWS IoT
                        payload = {"public_key": pub, "keypair_hash": keypair_hash}
                        payload_bytes = cbor2.dumps(payload)
                        signature = sign_message(payload_bytes)
                        signed_payload = {'data': payload, 'signature': signature}

                        self.iot_client.publish(
                            topic=f"{IOT_TOPIC_PREFIX}/dilithium/keygen",
                            qos=1,
                            payload=cbor2.dumps(signed_payload)
                        )

                        logger.info(f"Generated Dilithium keypair: public_key={pub[:16]}...")
                        return pub, encrypted_sec
                    except ClientError as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for keygen: {e}")
                            time.sleep(2 ** attempt)
                        else:
                            logger.error(f"Failed to generate keypair after {retries} attempts: {e}")
                            raise
            except Exception as e:
                logger.error(f"Dilithium keygen failed: {e}")
                raise

    def sign(self, message, private_key, retries=3):
        """Sign a message using the private key with QLDB logging."""
        with self.lock:
            if not isinstance(message, (str, bytes)) or not isinstance(private_key, str):
                logger.warning(f"Invalid input: message={type(message)}, private_key={private_key}")
                raise ValueError("Invalid message or private key")

            try:
                message_bytes = message.encode() if isinstance(message, str) else message
                message_hash = hashlib.sha3_512(message_bytes).hexdigest()
                cache_key = f"dilithium_sign_{message_hash}"
                cached_signature = self.redis_client.get(cache_key)
                if cached_signature:
                    logger.debug("Returning cached signature")
                    return json.loads(cached_signature)

                for attempt in range(retries):
                    try:
                        # Decrypt private key with KMS
                        encrypted_priv = base64.b64decode(private_key)
                        response = self.kms_client.decrypt(
                            CiphertextBlob=encrypted_priv,
                            KeyId=KMS_KEY_ID,
                            EncryptionAlgorithm='SYMMETRIC_DEFAULT'
                        )
                        priv_bytes = response['Plaintext']

                        # Load private key
                        private_key_obj = dilithium.Dilithium512PrivateKey.from_private_bytes(
                            priv_bytes, backend=default_backend()
                        )

                        # Sign message
                        signature = private_key_obj.sign(message_bytes)
                        sig = base64.b64encode(signature).decode()

                        # Generate ZKP for signature integrity
                        sig_hash = hashlib.sha3_512(cbor2.dumps(sig)).hexdigest()
                        zkp = generate_zkp(sig_hash)
                        if not verify_zkp(sig_hash, zkp):
                            logger.warning(f"ZKP verification failed for signature")
                            raise RuntimeError("Signature integrity verification failed")

                        # Log to QLDB
                        event_data = {
                            "message_hash": message_hash,
                            "signature": sig[:16],
                            "signature_hash": sig_hash,
                            "signature": sign_message(cbor2.dumps({"signature_hash": sig_hash}))
                        }
                        QLDBLogger.log_event("dilithium_sign", event_data)

                        # Cache signature for 300 seconds
                        self.redis_client.setex(cache_key, 300, json.dumps(sig))

                        # Publish to AWS IoT
                        payload = {"message_hash": message_hash, "signature": sig[:16]}
                        payload_bytes = cbor2.dumps(payload)
                        signature = sign_message(payload_bytes)
                        signed_payload = {'data': payload, 'signature': signature}

                        self.iot_client.publish(
                            topic=f"{IOT_TOPIC_PREFIX}/dilithium/sign",
                            qos=1,
                            payload=cbor2.dumps(signed_payload)
                        )

                        logger.info(f"Signed message: signature={sig[:16]}...")
                        return sig
                    except ClientError as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for sign: {e}")
                            time.sleep(2 ** attempt)
                        else:
                            logger.error(f"Failed to sign message after {retries} attempts: {e}")
                            raise
            except Exception as e:
                logger.error(f"Dilithium signing failed: {e}")
                raise

    def verify(self, message, signature, public_key, retries=3):
        """Verify a signature with the given public key and message."""
        with self.lock:
            if not isinstance(message, (str, bytes)) or not isinstance(signature, str) or not isinstance(public_key, str):
                logger.warning(f"Invalid input: message={type(message)}, signature={signature}, public_key={public_key}")
                raise ValueError("Invalid message, signature, or public key")

            try:
                message_bytes = message.encode() if isinstance(message, str) else message
                message_hash = hashlib.sha3_512(message_bytes).hexdigest()
                cache_key = f"dilithium_verify_{message_hash}_{signature[:16]}"
                cached_result = self.redis_client.get(cache_key)
                if cached_result:
                    logger.debug("Returning cached verification result")
                    return json.loads(cached_result)

                for attempt in range(retries):
                    try:
                        sig_bytes = base64.b64decode(signature)
                        pub_bytes = base64.b64decode(public_key)

                        # Load public key
                        public_key_obj = dilithium.Dilithium512PublicKey.from_public_bytes(
                            pub_bytes, backend=default_backend()
                        )

                        # Verify signature
                        try:
                            public_key_obj.verify(message_bytes, sig_bytes)
                            is_valid = True
                        except Exception:
                            is_valid = False

                        # Generate ZKP for verification integrity
                        verify_data = {"message_hash": message_hash, "is_valid": is_valid}
                        verify_hash = hashlib.sha3_512(cbor2.dumps(verify_data)).hexdigest()
                        zkp = generate_zkp(verify_hash)
                        if not verify_zkp(verify_hash, zkp):
                            logger.warning(f"ZKP verification failed for signature verification")
                            return False

                        # Log to QLDB
                        event_data = {
                            "message_hash": message_hash,
                            "signature": signature[:16],
                            "is_valid": is_valid,
                            "signature": sign_message(cbor2.dumps({"verify_hash": verify_hash}))
                        }
                        QLDBLogger.log_event("dilithium_verify", event_data)

                        # Cache result for 300 seconds
                        self.redis_client.setex(cache_key, 300, json.dumps(is_valid))

                        # Publish to AWS IoT
                        payload = {"message_hash": message_hash, "signature": signature[:16], "is_valid": is_valid}
                        payload_bytes = cbor2.dumps(payload)
                        signature = sign_message(payload_bytes)
                        signed_payload = {'data': payload, 'signature': signature}

                        self.iot_client.publish(
                            topic=f"{IOT_TOPIC_PREFIX}/dilithium/verify",
                            qos=1,
                            payload=cbor2.dumps(signed_payload)
                        )

                        logger.info(f"Signature verification: message_hash={message_hash[:16]}..., is_valid={is_valid}")
                        return is_valid
                    except ClientError as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for verify: {e}")
                            time.sleep(2 ** attempt)
                        else:
                            logger.error(f"Failed to verify signature after {retries} attempts: {e}")
                            raise
            except Exception as e:
                logger.error(f"Dilithium verification failed: {e}")
                return False

# Example usage
if __name__ == "__main__":
    signer = DilithiumSigner()
    pub, priv = signer.keygen()
    message = "Hello, world!"
    signature = signer.sign(message, priv)
    is_valid = signer.verify(message, signature, pub)
    print(f"Dilithium signature verification: {'Valid' if is_valid else 'Invalid'}")