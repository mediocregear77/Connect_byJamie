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
from security_core.pqc.dilithium import sign_message
from security_core.zk_snark.zkp import generate_zkp, verify_zkp
import hashlib
import time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import kyber
from cryptography.hazmat.backends import default_backend

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/kyber.log')
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
KMS_KEY_ID = os.getenv('KMS_KEY_ID', '')
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')
IOT_TOPIC_PREFIX = os.getenv('IOT_TOPIC_PREFIX', 'mesh')

class KyberKEM:
    """
    Kyber Key Encapsulation Mechanism interface using pycryptodome.
    Supports keygen, encaps, decaps with quantum-secure integration.
    """

    def __init__(self):
        self.lock = threading.Lock()
        self.redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
        self.kms_client = boto3.client('kms', region_name=AWS_REGION)
        self.iot_client = boto3.client('iot-data', region_name=AWS_REGION)

    def keygen(self, retries=3):
        """Generate a Kyber keypair with KMS storage and QLDB logging."""
        with self.lock:
            try:
                cache_key = "kyber_keypair"
                cached_keypair = self.redis_client.get(cache_key)
                if cached_keypair:
                    pub, sec = json.loads(cached_keypair)
                    logger.debug("Returning cached Kyber keypair")
                    return pub, sec

                for attempt in range(retries):
                    try:
                        # Generate Kyber keypair using pycryptodome
                        private_key = kyber.Kyber512.generate_private_key(backend=default_backend())
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

                        # Store secret key in KMS
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
                        QLDBLogger.log_event("kyber_keygen", event_data)

                        # Cache keypair for 3600 seconds
                        self.redis_client.setex(cache_key, 3600, json.dumps((pub, encrypted_sec)))

                        # Publish to AWS IoT
                        payload = {"public_key": pub, "keypair_hash": keypair_hash}
                        payload_bytes = cbor2.dumps(payload)
                        signature = sign_message(payload_bytes)
                        signed_payload = {'data': payload, 'signature': signature}

                        self.iot_client.publish(
                            topic=f"{IOT_TOPIC_PREFIX}/kyber/keygen",
                            qos=1,
                            payload=cbor2.dumps(signed_payload)
                        )

                        logger.info(f"Generated Kyber keypair: public_key={pub[:16]}...")
                        return pub, encrypted_sec
                    except ClientError as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for keygen: {e}")
                            time.sleep(2 ** attempt)
                        else:
                            logger.error(f"Failed to generate keypair after {retries} attempts: {e}")
                            raise
            except Exception as e:
                logger.error(f"Kyber keygen failed: {e}")
                raise

    def encapsulate(self, public_key, retries=3):
        """Encapsulate a symmetric key to a Kyber public key with QLDB logging."""
        with self.lock:
            if not isinstance(public_key, str):
                logger.warning(f"Invalid public key: {public_key}")
                raise ValueError("Invalid public key")

            try:
                pub_bytes = base64.b64decode(public_key)
                cache_key = f"kyber_encaps_{hashlib.sha3_512(pub_bytes).hexdigest()}"
                cached_result = self.redis_client.get(cache_key)
                if cached_result:
                    ct, ss = json.loads(cached_result)
                    logger.debug("Returning cached encapsulation")
                    return ct, ss

                for attempt in range(retries):
                    try:
                        # Load public key
                        public_key_obj = kyber.Kyber512PublicKey.from_public_bytes(pub_bytes, backend=default_backend())

                        # Perform encapsulation
                        ciphertext, shared_secret = public_key_obj.encapsulate()

                        ct = base64.b64encode(ciphertext).decode()
                        ss = base64.b64encode(shared_secret).decode()

                        # Generate ZKP for encapsulation integrity
                        encap_hash = hashlib.sha3_512(cbor2.dumps([ct, ss])).hexdigest()
                        zkp = generate_zkp(encap_hash)
                        if not verify_zkp(encap_hash, zkp):
                            logger.warning(f"ZKP verification failed for encapsulation")
                            raise RuntimeError("Encapsulation integrity verification failed")

                        # Log to QLDB
                        event_data = {
                            "encap_hash": encap_hash,
                            "public_key": public_key[:16],
                            "signature": sign_message(cbor2.dumps({"encap_hash": encap_hash}))
                        }
                        QLDBLogger.log_event("kyber_encapsulate", event_data)

                        # Cache result for 300 seconds
                        self.redis_client.setex(cache_key, 300, json.dumps((ct, ss)))

                        # Publish to AWS IoT
                        payload = {"ciphertext": ct, "public_key": public_key[:16], "encap_hash": encap_hash}
                        payload_bytes = cbor2.dumps(payload)
                        signature = sign_message(payload_bytes)
                        signed_payload = {'data': payload, 'signature': signature}

                        self.iot_client.publish(
                            topic=f"{IOT_TOPIC_PREFIX}/kyber/encapsulate",
                            qos=1,
                            payload=cbor2.dumps(signed_payload)
                        )

                        logger.info(f"Encapsulated symmetric key for public_key={public_key[:16]}...")
                        return ct, ss
                    except ClientError as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for encapsulate: {e}")
                            time.sleep(2 ** attempt)
                        else:
                            logger.error(f"Failed to encapsulate after {retries} attempts: {e}")
                            raise
            except Exception as e:
                logger.error(f"Kyber encapsulation failed: {e}")
                raise

    def decapsulate(self, ciphertext, secret_key, retries=3):
        """Decapsulate a ciphertext using the Kyber secret key with QLDB logging."""
        with self.lock:
            if not isinstance(ciphertext, str) or not isinstance(secret_key, str):
                logger.warning(f"Invalid input: ciphertext={ciphertext}, secret_key={secret_key}")
                raise ValueError("Invalid ciphertext or secret key")

            try:
                ct_bytes = base64.b64decode(ciphertext)
                cache_key = f"kyber_decaps_{hashlib.sha3_512(ct_bytes).hexdigest()}"
                cached_ss = self.redis_client.get(cache_key)
                if cached_ss:
                    logger.debug("Returning cached shared secret")
                    return json.loads(cached_ss)

                for attempt in range(retries):
                    try:
                        # Decrypt secret key with KMS
                        encrypted_sec = base64.b64decode(secret_key)
                        response = self.kms_client.decrypt(
                            CiphertextBlob=encrypted_sec,
                            KeyId=KMS_KEY_ID,
                            EncryptionAlgorithm='SYMMETRIC_DEFAULT'
                        )
                        sec_bytes = response['Plaintext']

                        # Load private key
                        private_key = kyber.Kyber512PrivateKey.from_private_bytes(sec_bytes, backend=default_backend())

                        # Perform decapsulation
                        shared_secret = private_key.decapsulate(ct_bytes)

                        ss = base64.b64encode(shared_secret).decode()

                        # Generate ZKP for decapsulation integrity
                        decap_hash = hashlib.sha3_512(cbor2.dumps(ss)).hexdigest()
                        zkp = generate_zkp(decap_hash)
                        if not verify_zkp(decap_hash, zkp):
                            logger.warning(f"ZKP verification failed for decapsulation")
                            raise RuntimeError("Decapsulation integrity verification failed")

                        # Log to QLDB
                        event_data = {
                            "decap_hash": decap_hash,
                            "ciphertext": ciphertext[:16],
                            "signature": sign_message(cbor2.dumps({"decap_hash": decap_hash}))
                        }
                        QLDBLogger.log_event("kyber_decapsulate", event_data)

                        # Cache shared secret for 300 seconds
                        self.redis_client.setex(cache_key, 300, json.dumps(ss))

                        # Publish to AWS IoT
                        payload = {"ciphertext": ciphertext[:16], "decap_hash": decap_hash}
                        payload_bytes = cbor2.dumps(payload)
                        signature = sign_message(payload_bytes)
                        signed_payload = {'data': payload, 'signature': signature}

                        self.iot_client.publish(
                            topic=f"{IOT_TOPIC_PREFIX}/kyber/decapsulate",
                            qos=1,
                            payload=cbor2.dumps(signed_payload)
                        )

                        logger.info(f"Decapsulated shared secret for ciphertext={ciphertext[:16]}...")
                        return ss
                    except ClientError as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for decapsulate: {e}")
                            time.sleep(2 ** attempt)
                        else:
                            logger.error(f"Failed to decapsulate after {retries} attempts: {e}")
                            raise
            except Exception as e:
                logger.error(f"Kyber decapsulation failed: {e}")
                raise

# Example usage
if __name__ == "__main__":
    kyber = KyberKEM()
    pub, sec = kyber.keygen()
    ct, ss_enc = kyber.encapsulate(pub)
    ss_dec = kyber.decapsulate(ct, sec)
    print(f"Kyber KEM demo: Shared secret match: {ss_enc == ss_dec}")