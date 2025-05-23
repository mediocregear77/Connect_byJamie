import base64
import hashlib
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
import orjson
import time
from jsonschema import validate, ValidationError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/snark_utils.log')
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')
IOT_TOPIC_PREFIX = os.getenv('IOT_TOPIC_PREFIX', 'mesh')

# JSON schema for proof objects
PROOF_SCHEMA = {
    "type": "object",
    "properties": {
        "proof": {"type": "object"},
        "public": {"type": "string"},
        "signal": {"type": "string"},
        "encrypted_witness": {"type": "string"},
        "signature": {"type": "string"},
        "public_key": {"type": "string"},
        "zkp": {"type": "string"}
    },
    "required": ["proof", "public", "signal"]
}

class SnarkUtils:
    """Utilities for zk-SNARK operations with secure integration."""

    def __init__(self):
        self.lock = threading.Lock()
        self.redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
        self.iot_client = boto3.client('iot-data', region_name=AWS_REGION)
        self.signer = DilithiumSigner()

    def serialize_proof(self, proof_obj: dict, retries=3) -> str:
        """
        Serializes a proof object to a base64-encoded JSON string with Dilithium signing.
        """
        with self.lock:
            if not isinstance(proof_obj, dict):
                logger.warning(f"Invalid proof object: {proof_obj}")
                raise ValueError("Invalid proof object")

            try:
                # Validate proof object
                validate(instance=proof_obj, schema=PROOF_SCHEMA)

                proof_hash = hashlib.sha3_512(cbor2.dumps(proof_obj)).hexdigest()
                cache_key = f"serialized_proof_{proof_hash}"
                cached_serialized = self.redis_client.get(cache_key)
                if cached_serialized:
                    logger.debug("Returning cached serialized proof")
                    return cached_serialized

                for attempt in range(retries):
                    try:
                        # Serialize with orjson for performance
                        proof_json = orjson.dumps(proof_obj, option=orjson.OPT_SORT_KEYS)
                        serialized = base64.b64encode(proof_json).decode('utf-8')

                        # Sign serialized proof
                        pub_key, priv_key = self.signer.keygen()
                        signature = self.signer.sign(proof_json, priv_key)

                        # Log to QLDB
                        event_data = {
                            "proof_hash": proof_hash,
                            "serialized_hash": hashlib.sha3_512(serialized.encode()).hexdigest(),
                            "signature": sign_message(cbor2.dumps({"proof_hash": proof_hash}))
                        }
                        QLDBLogger.log_event("snark_serialize_proof", event_data)

                        # Cache serialized proof for 300 seconds
                        self.redis_client.setex(cache_key, 300, serialized)

                        # Publish to AWS IoT
                        payload = {
                            "proof_hash": proof_hash,
                            "serialized_length": len(serialized),
                            "public_key": pub_key[:16]
                        }
                        payload_bytes = cbor2.dumps(payload)
                        signature = sign_message(payload_bytes)
                        signed_payload = {'data': payload, 'signature': signature}

                        self.iot_client.publish(
                            topic=f"{IOT_TOPIC_PREFIX}/snark/serialize",
                            qos=1,
                            payload=cbor2.dumps(signed_payload)
                        )

                        logger.info(f"Serialized proof: proof_hash={proof_hash[:16]}...")
                        return serialized
                    except ClientError as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for serialize_proof: {e}")
                            time.sleep(2 ** attempt)
                        else:
                            logger.error(f"Failed to serialize proof after {retries} attempts: {e}")
                            raise
            except ValidationError as e:
                logger.error(f"Invalid proof object schema: {e}")
                raise
            except Exception as e:
                logger.error(f"Failed to serialize proof: {e}")
                raise

    def deserialize_proof(self, proof_str: str, retries=3) -> dict:
        """
        Deserializes a base64-encoded JSON string back to a proof object.
        """
        with self.lock:
            if not isinstance(proof_str, str) or not proof_str.strip():
                logger.warning(f"Invalid proof string: {proof_str}")
                raise ValueError("Invalid proof string")

            try:
                proof_hash = hashlib.sha3_512(proof_str.encode()).hexdigest()
                cache_key = f"deserialized_proof_{proof_hash}"
                cached_deserialized = self.redis_client.get(cache_key)
                if cached_deserialized:
                    logger.debug("Returning cached deserialized proof")
                    return json.loads(cached_deserialized)

                for attempt in range(retries):
                    try:
                        proof_json = base64.b64decode(proof_str.encode('utf-8')).decode('utf-8')
                        proof_obj = orjson.loads(proof_json)

                        # Validate proof object
                        validate(instance=proof_obj, schema=PROOF_SCHEMA)

                        # Log to QLDB
                        event_data = {
                            "proof_hash": proof_hash,
                            "statement": proof_obj.get("public", "")[:16],
                            "signature": sign_message(cbor2.dumps({"proof_hash": proof_hash}))
                        }
                        QLDBLogger.log_event("snark_deserialize_proof", event_data)

                        # Cache deserialized proof for 300 seconds
                        self.redis_client.setex(cache_key, 300, json.dumps(proof_obj))

                        # Publish to AWS IoT
                        payload = {
                            "proof_hash": proof_hash,
                            "statement": proof_obj.get("public", "")[:16]
                        }
                        payload_bytes = cbor2.dumps(payload)
                        signature = sign_message(payload_bytes)
                        signed_payload = {'data': payload, 'signature': signature}

                        self.iot_client.publish(
                            topic=f"{IOT_TOPIC_PREFIX}/snark/deserialize",
                            qos=1,
                            payload=cbor2.dumps(signed_payload)
                        )

                        logger.info(f"Deserialized proof: proof_hash={proof_hash[:16]}...")
                        return proof_obj
                    except ClientError as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for deserialize_proof: {e}")
                            time.sleep(2 ** attempt)
                        else:
                            logger.error(f"Failed to deserialize proof after {retries} attempts: {e}")
                            raise
            except ValidationError as e:
                logger.error(f"Invalid proof object schema after deserialization: {e}")
                raise
            except Exception as e:
                logger.error(f"Failed to deserialize proof: {e}")
                raise

    def hash_statement(self, statement: str) -> str:
        """
        Hashes a statement for use in proof generation/verification.
        Returns a hex SHA3-256 digest with QLDB logging.
        """
        with self.lock:
            if not isinstance(statement, str) or not statement.strip():
                logger.warning(f"Invalid statement: {statement}")
                raise ValueError("Invalid statement")

            try:
                cache_key = f"statement_hash_{hashlib.sha3_256(statement.encode()).hexdigest()}"
                cached_hash = self.redis_client.get(cache_key)
                if cached_hash:
                    logger.debug("Returning cached statement hash")
                    return cached_hash

                statement_hash = hashlib.sha3_256(statement.encode('utf-8')).hexdigest()

                # Log to QLDB
                event_data = {
                    "statement_hash": statement_hash,
                    "statement": statement[:16],
                    "signature": sign_message(cbor2.dumps({"statement_hash": statement_hash}))
                }
                QLDBLogger.log_event("snark_hash_statement", event_data)

                # Cache hash for 300 seconds
                self.redis_client.setex(cache_key, 300, statement_hash)

                logger.debug(f"Hashed statement: statement={statement[:16]}..., hash={statement_hash[:16]}...")
                return statement_hash
            except Exception as e:
                logger.error(f"Failed to hash statement: {e}")
                raise

    def get_curve_params(self, curve_name: str = "bn128") -> dict:
        """
        Returns curve parameters for given curve_name with caching.
        Supports bn128 and BLS12-381.
        """
        with self.lock:
            if not isinstance(curve_name, str) or not curve_name.strip():
                logger.warning(f"Invalid curve name: {curve_name}")
                raise ValueError("Invalid curve name")

            try:
                cache_key = f"curve_params_{curve_name}"
                cached_params = self.redis_client.get(cache_key)
                if cached_params:
                    logger.debug(f"Returning cached curve params for {curve_name}")
                    return json.loads(cached_params)

                curves = {
                    "bn128": {
                        "field_size": "21888242871839275222246405745257275088548364400416034343698204186575808495617",
                        "generator": "1",
                        "order": "21888242871839275222246405745257275088696311157297823662689037894645226208583"
                    },
                    "bls12_381": {
                        "field_size": "52435875175126190479447740508185965837690552500527637822603658699938581184513",
                        "generator": "1",
                        "order": "52435875175126190479447740508185965837690552500527637822603658699938581184513"
                    }
                }

                params = curves.get(curve_name, {})
                if not params:
                    logger.warning(f"Unsupported curve: {curve_name}")
                    raise ValueError(f"Unsupported curve: {curve_name}")

                # Log to QLDB
                event_data = {
                    "curve_name": curve_name,
                    "params_hash": hashlib.sha3_512(cbor2.dumps(params)).hexdigest(),
                    "signature": sign_message(cbor2.dumps({"curve_name": curve_name}))
                }
                QLDBLogger.log_event("snark_curve_params", event_data)

                # Cache params for 3600 seconds
                self.redis_client.setex(cache_key, 3600, json.dumps(params))

                logger.info(f"Retrieved curve params for {curve_name}")
                return params
            except Exception as e:
                logger.error(f"Failed to get curve params for {curve_name}: {e}")
                raise

# Example usage
if __name__ == "__main__":
    utils = SnarkUtils()
    test_proof = {"proof": {"pi_a": [1, 2, 3], "pi_b": [4, 5, 6], "pi_c": [7, 8, 9]}, "public": "test", "signal": "signal"}
    serialized = utils.serialize_proof(test_proof)
    print("Serialized:", serialized)
    deserialized = utils.deserialize_proof(serialized)
    print("Deserialized:", deserialized)
    print("SHA3 statement hash:", utils.hash_statement("test-statement"))
    print("Curve params:", utils.get_curve_params("bn128"))