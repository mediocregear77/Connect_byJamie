import logging
import threading
from dotenv import load_dotenv
import os
import redis
import cbor2
import boto3
from botocore.exceptions import ClientError
from audit_core.audit_log.qldb_logger import QLDBLogger
from security_core.pqc.dilithium import DilithiumSigner
from security_core.zk_snark.zkp import generate_zkp, verify_zkp
import hashlib
import time
import json
import base64
import pyhelib  # Assumed Python bindings for HElib; replace with actual library in production

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/helib_wrapper.log')
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
KMS_KEY_ID = os.getenv('KMS_KEY_ID', '')
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')
IOT_TOPIC_PREFIX = os.getenv('IOT_TOPIC_PREFIX', 'mesh')

class HElibWrapper:
    """
    Python wrapper for HElib homomorphic encryption operations using pyhelib.
    Supports encryption, decryption, addition, multiplication, and comparison.
    """

    def __init__(self):
        self.lock = threading.Lock()
        self.redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
        self.kms_client = boto3.client('kms', region_name=AWS_REGION)
        self.iot_client = boto3.client('iot-data', region_name=AWS_REGION)
        self.signer = DilithiumSigner()
        self.context = None
        self._init_helib()

    def _init_helib(self):
        """Initialize HElib context."""
        try:
            # Initialize HElib context with CKKS scheme for real numbers
            self.context = pyhelib.Context(
                m=16384,  # Cyclotomic polynomial degree
                p=2,      # Plaintext modulus
                r=20      # Bits of precision
            )
            self.context.enable_bootstrapping()
            logger.info("Initialized HElib context")
        except Exception as e:
            logger.error(f"Failed to initialize HElib context: {e}")
            raise

    def encrypt(self, public_key: str, plaintext: str, retries=3) -> str:
        """
        Encrypt plaintext using the provided public key.
        Returns ciphertext as a base64 string.
        """
        with self.lock:
            if not isinstance(public_key, str) or not isinstance(plaintext, str):
                logger.warning(f"Invalid input: public_key={public_key}, plaintext={plaintext}")
                raise ValueError("Invalid public key or plaintext")

            try:
                plaintext_hash = hashlib.sha3_512(plaintext.encode()).hexdigest()
                cache_key = f"helib_ciphertext_{plaintext_hash}_{public_key[:16]}"
                cached_ciphertext = self.redis_client.get(cache_key)
                if cached_ciphertext:
                    logger.debug("Returning cached ciphertext")
                    return cached_ciphertext

                for attempt in range(retries):
                    try:
                        # Load public key
                        pub_bytes = base64.b64decode(public_key)
                        public_key_obj = pyhelib.PublicKey.from_bytes(pub_bytes, self.context)

                        # Encrypt plaintext
                        plaintext_value = float(plaintext) if plaintext.replace('.', '', 1).isdigit() else plaintext.encode()
                        ciphertext = public_key_obj.encrypt(plaintext_value)

                        # Serialize ciphertext
                        ct_bytes = ciphertext.to_bytes()
                        ct = base64.b64encode(ct_bytes).decode()

                        # Generate ZKP for ciphertext integrity
                        ct_hash = hashlib.sha3_512(ct_bytes).hexdigest()
                        zkp = generate_zkp(ct_hash)
                        if not verify_zkp(ct_hash, zkp):
                            logger.warning(f"ZKP verification failed for ciphertext")
                            raise RuntimeError("Ciphertext integrity verification failed")

                        # Sign ciphertext with Dilithium
                        pub_key, priv_key = self.signer.keygen()
                        signature = self.signer.sign(ct_bytes, priv_key)

                        # Log to QLDB
                        event_data = {
                            "plaintext_hash": plaintext_hash,
                            "ciphertext_hash": ct_hash,
                            "public_key": public_key[:16],
                            "signature": sign_message(cbor2.dumps({"ciphertext_hash": ct_hash}))
                        }
                        QLDBLogger.log_event("helib_encrypt", event_data)

                        # Cache ciphertext for 300 seconds
                        self.redis_client.setex(cache_key, 300, ct)

                        # Publish to AWS IoT
                        payload = {
                            "ciphertext_hash": ct_hash,
                            "public_key": public_key[:16],
                            "signature": signature[:16]
                        }
                        payload_bytes = cbor2.dumps(payload)
                        signature = sign_message(payload_bytes)
                        signed_payload = {'data': payload, 'signature': signature}

                        self.iot_client.publish(
                            topic=f"{IOT_TOPIC_PREFIX}/helib/encrypt",
                            qos=1,
                            payload=cbor2.dumps(signed_payload)
                        )

                        logger.info(f"Encrypted plaintext: ciphertext_hash={ct_hash[:16]}...")
                        return ct
                    except ClientError as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for encrypt: {e}")
                            time.sleep(2 ** attempt)
                        else:
                            logger.error(f"Failed to encrypt after {retries} attempts: {e}")
                            raise
            except Exception as e:
                logger.error(f"HElib encryption failed: {e}")
                raise

    def decrypt(self, private_key: str, ciphertext: str, retries=3) -> str:
        """
        Decrypt ciphertext using the provided private key.
        Returns plaintext.
        """
        with self.lock:
            if not isinstance(private_key, str) or not isinstance(ciphertext, str):
                logger.warning(f"Invalid input: private_key={private_key}, ciphertext={ciphertext}")
                raise ValueError("Invalid private key or ciphertext")

            try:
                ct_hash = hashlib.sha3_512(ciphertext.encode()).hexdigest()
                cache_key = f"helib_plaintext_{ct_hash}_{private_key[:16]}"
                cached_plaintext = self.redis_client.get(cache_key)
                if cached_plaintext:
                    logger.debug("Returning cached plaintext")
                    return cached_plaintext

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
                        private_key_obj = pyhelib.SecretKey.from_bytes(priv_bytes, self.context)

                        # Deserialize ciphertext
                        ct_bytes = base64.b64decode(ciphertext)
                        ciphertext_obj = pyhelib.Ciphertext.from_bytes(ct_bytes, self.context)

                        # Decrypt
                        plaintext = private_key_obj.decrypt(ciphertext_obj)
                        plaintext_str = str(plaintext) if isinstance(plaintext, (int, float)) else plaintext.decode()

                        # Generate ZKP for plaintext integrity
                        pt_hash = hashlib.sha3_512(plaintext_str.encode()).hexdigest()
                        zkp = generate_zkp(pt_hash)
                        if not verify_zkp(pt_hash, zkp):
                            logger.warning(f"ZKP verification failed for plaintext")
                            raise RuntimeError("Plaintext integrity verification failed")

                        # Log to QLDB
                        event_data = {
                            "ciphertext_hash": ct_hash,
                            "plaintext_hash": pt_hash,
                            "signature": sign_message(cbor2.dumps({"plaintext_hash": pt_hash}))
                        }
                        QLDBLogger.log_event("helib_decrypt", event_data)

                        # Cache plaintext for 300 seconds
                        self.redis_client.setex(cache_key, 300, plaintext_str)

                        # Publish to AWS IoT
                        payload = {
                            "ciphertext_hash": ct_hash,
                            "plaintext_hash": pt_hash
                        }
                        payload_bytes = cbor2.dumps(payload)
                        signature = sign_message(payload_bytes)
                        signed_payload = {'data': payload, 'signature': signature}

                        self.iot_client.publish(
                            topic=f"{IOT_TOPIC_PREFIX}/helib/decrypt",
                            qos=1,
                            payload=cbor2.dumps(signed_payload)
                        )

                        logger.info(f"Decrypted ciphertext: plaintext_hash={pt_hash[:16]}...")
                        return plaintext_str
                    except ClientError as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for decrypt: {e}")
                            time.sleep(2 ** attempt)
                        else:
                            logger.error(f"Failed to decrypt after {retries} attempts: {e}")
                            raise
            except Exception as e:
                logger.error(f"HElib decryption failed: {e}")
                raise

    def add(self, ciphertexts: list, retries=3) -> str:
        """
        Homomorphically adds a list of ciphertexts.
        Returns a new ciphertext as a base64 string.
        """
        with self.lock:
            if not isinstance(ciphertexts, list) or not all(isinstance(ct, str) for ct in ciphertexts):
                logger.warning(f"Invalid ciphertexts: {ciphertexts}")
                raise ValueError("Invalid ciphertexts")

            try:
                ct_hashes = [hashlib.sha3_512(ct.encode()).hexdigest() for ct in ciphertexts]
                input_hash = hashlib.sha3_512(cbor2.dumps(ct_hashes)).hexdigest()
                cache_key = f"helib_add_{input_hash}"
                cached_result = self.redis_client.get(cache_key)
                if cached_result:
                    logger.debug("Returning cached added ciphertext")
                    return cached_result

                for attempt in range(retries):
                    try:
                        # Deserialize ciphertexts
                        ct_objects = [
                            pyhelib.Ciphertext.from_bytes(base64.b64decode(ct), self.context)
                            for ct in ciphertexts
                        ]

                        # Perform homomorphic addition
                        result_ct = ct_objects[0]
                        for ct in ct_objects[1:]:
                            result_ct += ct

                        # Serialize result
                        result_bytes = result_ct.to_bytes()
                        result = base64.b64encode(result_bytes).decode()

                        # Generate ZKP for result integrity
                        result_hash = hashlib.sha3_512(result_bytes).hexdigest()
                        zkp = generate_zkp(result_hash)
                        if not verify_zkp(result_hash, zkp):
                            logger.warning(f"ZKP verification failed for added ciphertext")
                            raise RuntimeError("Added ciphertext integrity verification failed")

                        # Log to QLDB
                        event_data = {
                            "input_hash": input_hash,
                            "result_hash": result_hash,
                            "signature": sign_message(cbor2.dumps({"result_hash": result_hash}))
                        }
                        QLDBLogger.log_event("helib_add", event_data)

                        # Cache result for 300 seconds
                        self.redis_client.setex(cache_key, 300, result)

                        # Publish to AWS IoT
                        payload = {
                            "input_hash": input_hash,
                            "result_hash": result_hash
                        }
                        payload_bytes = cbor2.dumps(payload)
                        signature = sign_message(payload_bytes)
                        signed_payload = {'data': payload, 'signature': signature}

                        self.iot_client.publish(
                            topic=f"{IOT_TOPIC_PREFIX}/helib/add",
                            qos=1,
                            payload=cbor2.dumps(signed_payload)
                        )

                        logger.info(f"Homomorphically added {len(ciphertexts)} ciphertexts: result_hash={result_hash[:16]}...")
                        return result
                    except ClientError as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for add: {e}")
                            time.sleep(2 ** attempt)
                        else:
                            logger.error(f"Failed to add ciphertexts after {retries} attempts: {e}")
                            raise
            except Exception as e:
                logger.error(f"HElib addition failed: {e}")
                raise

    def multiply(self, ciphertexts: list, retries=3) -> str:
        """
        Homomorphically multiplies a list of ciphertexts.
        Returns a new ciphertext as a base64 string.
        """
        with self.lock:
            if not isinstance(ciphertexts, list) or not all(isinstance(ct, str) for ct in ciphertexts):
                logger.warning(f"Invalid ciphertexts: {ciphertexts}")
                raise ValueError("Invalid ciphertexts")

            try:
                ct_hashes = [hashlib.sha3_512(ct.encode()).hexdigest() for ct in ciphertexts]
                input_hash = hashlib.sha3_512(cbor2.dumps(ct_hashes)).hexdigest()
                cache_key = f"helib_multiply_{input_hash}"
                cached_result = self.redis_client.get(cache_key)
                if cached_result:
                    logger.debug("Returning cached multiplied ciphertext")
                    return cached_result

                for attempt in range(retries):
                    try:
                        # Deserialize ciphertexts
                        ct_objects = [
                            pyhelib.Ciphertext.from_bytes(base64.b64decode(ct), self.context)
                            for ct in ciphertexts
                        ]

                        # Perform homomorphic multiplication
                        result_ct = ct_objects[0]
                        for ct in ct_objects[1:]:
                            result_ct *= ct

                        # Serialize result
                        result_bytes = result_ct.to_bytes()
                        result = base64.b64encode(result_bytes).decode()

                        # Generate ZKP for result integrity
                        result_hash = hashlib.sha3_512(result_bytes).hexdigest()
                        zkp = generate_zkp(result_hash)
                        if not verify_zkp(result_hash, zkp):
                            logger.warning(f"ZKP verification failed for multiplied ciphertext")
                            raise RuntimeError("Multiplied ciphertext integrity verification failed")

                        # Log to QLDB
                        event_data = {
                            "input_hash": input_hash,
                            "result_hash": result_hash,
                            "signature": sign_message(cbor2.dumps({"result_hash": result_hash}))
                        }
                        QLDBLogger.log_event("helib_multiply", event_data)

                        # Cache result for 300 seconds
                        self.redis_client.setex(cache_key, 300, result)

                        # Publish to AWS IoT
                        payload = {
                            "input_hash": input_hash,
                            "result_hash": result_hash
                        }
                        payload_bytes = cbor2.dumps(payload)
                        signature = sign_message(payload_bytes)
                        signed_payload = {'data': payload, 'signature': signature}

                        self.iot_client.publish(
                            topic=f"{IOT_TOPIC_PREFIX}/helib/multiply",
                            qos=1,
                            payload=cbor2.dumps(signed_payload)
                        )

                        logger.info(f"Homomorphically multiplied {len(ciphertexts)} ciphertexts: result_hash={result_hash[:16]}...")
                        return result
                    except ClientError as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for multiply: {e}")
                            time.sleep(2 ** attempt)
                        else:
                            logger.error(f"Failed to multiply ciphertexts after {retries} attempts: {e}")
                            raise
            except Exception as e:
                logger.error(f"HElib multiplication failed: {e}")
                raise

    def compare(self, ciphertext1: str, ciphertext2: str, retries=3) -> bool:
        """
        Homomorphically compares two ciphertexts for equality.
        Returns True if equal, False otherwise.
        """
        with self.lock:
            if not isinstance(ciphertext1, str) or not isinstance(ciphertext2, str):
                logger.warning(f"Invalid ciphertexts: ciphertext1={ciphertext1}, ciphertext2={ciphertext2}")
                raise ValueError("Invalid ciphertexts")

            try:
                input_hash = hashlib.sha3_512(cbor2.dumps([ciphertext1, ciphertext2])).hexdigest()
                cache_key = f"helib_compare_{input_hash}"
                cached_result = self.redis_client.get(cache_key)
                if cached_result:
                    logger.debug("Returning cached comparison result")
                    return json.loads(cached_result)

                for attempt in range(retries):
                    try:
                        # Deserialize ciphertexts
                        ct1 = pyhelib.Ciphertext.from_bytes(base64.b64decode(ciphertext1), self.context)
                        ct2 = pyhelib.Ciphertext.from_bytes(base64.b64decode(ciphertext2), self.context)

                        # Perform homomorphic comparison (simplified: subtract and check zero)
                        diff = ct1 - ct2
                        is_equal = diff.is_zero()

                        # Generate ZKP for comparison integrity
                        result_hash = hashlib.sha3_512(cbor2.dumps(is_equal)).hexdigest()
                        zkp = generate_zkp(result_hash)
                        if not verify_zkp(result_hash, zkp):
                            logger.warning(f"ZKP verification failed for comparison")
                            raise RuntimeError("Comparison integrity verification failed")

                        # Log to QLDB
                        event_data = {
                            "input_hash": input_hash,
                            "result_hash": result_hash,
                            "is_equal": is_equal,
                            "signature": sign_message(cbor2.dumps({"result_hash": result_hash}))
                        }
                        QLDBLogger.log_event("helib_compare", event_data)

                        # Cache result for 300 seconds
                        self.redis_client.setex(cache_key, 300, json.dumps(is_equal))

                        # Publish to AWS IoT
                        payload = {
                            "input_hash": input_hash,
                            "result_hash": result_hash,
                            "is_equal": is_equal
                        }
                        payload_bytes = cbor2.dumps(payload)
                        signature = sign_message(payload_bytes)
                        signed_payload = {'data': payload, 'signature': signature}

                        self.iot_client.publish(
                            topic=f"{IOT_TOPIC_PREFIX}/helib/compare",
                            qos=1,
                            payload=cbor2.dumps(signed_payload)
                        )

                        logger.info(f"Homomorphically compared ciphertexts: is_equal={is_equal}")
                        return is_equal
                    except ClientError as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for compare: {e}")
                            time.sleep(2 ** attempt)
                        else:
                            logger.error(f"Failed to compare ciphertexts after {retries} attempts: {e}")
                            raise
            except Exception as e:
                logger.error(f"HElib comparison failed: {e}")
                raise