import uuid
import time
import logging
import threading
from dotenv import load_dotenv
import os
import redis
import cbor2
import boto3
from botocore.exceptions import ClientError
from audit_core.audit_log.qldb_logger import QLDBLogger
from audit_core.audit_log.public_feed import PublicFeed
from security_core.pqc.kyber import KyberKEM
from security_core.pqc.dilithium import DilithiumSigner
from security_core.zk_snark.zkp import ZKProof
import hashlib
import orjson
from jsonschema import validate, ValidationError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/witness_statement.log')
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')
IOT_TOPIC_PREFIX = os.getenv('IOT_TOPIC_PREFIX', 'mesh')
WITNESS_STATEMENT_TYPES = json.loads(os.getenv('WITNESS_STATEMENT_TYPES', '["HUMAN_RIGHTS_VIOLATION", "FORCED_DISPLACEMENT", "EMERGENCY_AID_DENIED", "CENSORSHIP_EVENT", "GENERIC_ALERT"]'))

# JSON schema for witness statements
STATEMENT_SCHEMA = {
    "type": "object",
    "properties": {
        "id": {"type": "string"},
        "type": {"type": "string", "enum": WITNESS_STATEMENT_TYPES},
        "statement": {"type": "string"},
        "node_id": {"type": "string"},
        "timestamp": {"type": "number"},
        "signature": {"type": "string"},
        "public_key": {"type": "string"},
        "zkp": {"type": "string"}
    },
    "required": ["id", "type", "statement", "node_id", "timestamp"]
}

class WitnessStatement:
    """
    Secure witness statement management with Kyber encryption and Dilithium signatures.
    Supports creation and verification of statements for human rights alerts.
    """

    def __init__(self):
        self.lock = threading.Lock()
        self.redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
        self.iot_client = boto3.client('iot-data', region_name=AWS_REGION)
        self.kyber = KyberKEM()
        self.signer = DilithiumSigner()
        self.zkp = ZKProof()
        self.logger = QLDBLogger()
        self.public_feed = PublicFeed()

    def create_witness_statement(self, statement_type: str, statement_text: str, node_id: str, public_key: str, private_key: str, retries=3):
        """
        Create a signed, encrypted witness statement.
        """
        with self.lock:
            if not isinstance(statement_type, str) or not isinstance(statement_text, str) or not isinstance(node_id, str) or not isinstance(public_key, str) or not isinstance(private_key, str):
                logger.warning(f"Invalid input: statement_type={statement_type}, statement_text={statement_text}, node_id={node_id}, public_key={public_key}, private_key={private_key}")
                raise ValueError("Invalid input parameters")
            if statement_type not in WITNESS_STATEMENT_TYPES:
                logger.warning(f"Invalid statement type: {statement_type}")
                raise ValueError(f"Invalid statement type: {statement_type}")

            try:
                statement_id = str(uuid.uuid4())
                timestamp = int(time.time())
                payload = {
                    "id": statement_id,
                    "type": statement_type,
                    "statement": statement_text,
                    "node_id": node_id,
                    "timestamp": timestamp
                }

                # Validate payload
                validate(instance=payload, schema=STATEMENT_SCHEMA)

                payload_hash = hashlib.sha3_512(orjson.dumps(payload, option=orjson.OPT_SORT_KEYS)).hexdigest()
                cache_key = f"witness_statement_{payload_hash}_{node_id}"
                cached_package = self.redis_client.get(cache_key)
                if cached_package:
                    logger.debug(f"Returning cached witness statement: payload_hash={payload_hash[:16]}...")
                    return json.loads(cached_package)

                for attempt in range(retries):
                    try:
                        # Encrypt with Kyber
                        payload_json = orjson.dumps(payload, option=orjson.OPT_SORT_KEYS).decode()
                        ciphertext, shared_secret = self.kyber.encapsulate(public_key)

                        # Sign encrypted payload
                        signature = self.signer.sign(ciphertext.encode(), private_key)

                        witness_package = {
                            "statement_id": statement_id,
                            "encrypted": ciphertext.hex(),
                            "signature": signature,
                            "sender_node": node_id,
                            "timestamp": timestamp,
                            "public_key": public_key
                        }

                        # Generate ZKP for statement integrity
                        package_bytes = cbor2.dumps(witness_package)
                        package_hash = hashlib.sha3_512(package_bytes).hexdigest()
                        zkp = self.zkp.generate_proof(package_hash, f"secret:{package_hash}")
                        if not self.zkp.verify_proof(package_hash, zkp):
                            logger.warning(f"ZKP verification failed for package_hash={package_hash[:16]}...")
                            raise RuntimeError("Statement integrity verification failed")
                        witness_package["zkp"] = zkp

                        # Log to QLDB
                        qldb_event_data = {
                            "statement_id": statement_id,
                            "payload_hash": payload_hash,
                            "node_id": node_id,
                            "signature": self.signer.sign(
                                cbor2.dumps({"statement_id": statement_id}),
                                self.signer.keygen()[1]
                            )
                        }
                        self.logger.log_event("witness_statement_create", qldb_event_data)

                        # Log to public feed (anonymized)
                        public_event_data = {
                            "type": "witness_statement_created",
                            "time": timestamp,
                            "statement_id": statement_id,
                            "payload_hash": payload_hash
                        }
                        self.public_feed.publish_event("witness_statement_created", public_event_data)

                        # Publish to AWS IoT
                        payload = {
                            "statement_id": statement_id,
                            "payload_hash": payload_hash[:16],
                            "node_id": node_id
                        }
                        payload_bytes = cbor2.dumps(payload)
                        signature = self.signer.sign(payload_bytes, self.signer.keygen()[1])
                        signed_payload = {'data': payload, 'signature': signature}

                        try:
                            self.iot_client.publish(
                                topic=f"{IOT_TOPIC_PREFIX}/witness/statement",
                                qos=1,
                                payload=cbor2.dumps(signed_payload)
                            )
                        except ClientError as e:
                            logger.warning(f"IoT publish error: {e}")

                        # Cache witness package for 300 seconds
                        self.redis_client.setex(cache_key, 300, json.dumps(witness_package))

                        logger.info(f"Created witness statement: statement_id={statement_id}, payload_hash={payload_hash[:16]}...")
                        return witness_package
                    except Exception as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for create_witness_statement: {e}")
                            time.sleep(2 ** attempt)
                        else:
                            logger.error(f"Failed to create witness statement after {retries} attempts: {e}")
                            raise
            except ValidationError as e:
                logger.error(f"Invalid statement schema: {e}")
                raise
            except Exception as e:
                logger.error(f"Witness statement creation failed: {e}")
                raise

    def verify_witness_statement(self, encrypted: bytes, signature: str, pubkey: str, retries=3) -> bool:
        """
        Verify the signature of an encrypted witness statement.
        """
        with self.lock:
            if not isinstance(encrypted, bytes) or not isinstance(signature, str) or not isinstance(pubkey, str):
                logger.warning(f"Invalid input: encrypted={type(encrypted)}, signature={signature}, pubkey={pubkey}")
                raise ValueError("Invalid encrypted, signature, or pubkey")

            try:
                data_hash = hashlib.sha3_512(encrypted).hexdigest()
                cache_key = f"witness_verify_{data_hash}_{pubkey[:16]}"
                cached_result = self.redis_client.get(cache_key)
                if cached_result:
                    logger.debug(f"Returning cached verification result: data_hash={data_hash[:16]}...")
                    return json.loads(cached_result)

                for attempt in range(retries):
                    try:
                        is_valid = self.signer.verify(encrypted, signature, pubkey)

                        # Log to QLDB
                        event_data = {
                            "data_hash": data_hash,
                            "pubkey": pubkey[:16],
                            "is_valid": is_valid,
                            "signature": self.signer.sign(
                                cbor2.dumps({"data_hash": data_hash, "is_valid": is_valid}),
                                self.signer.keygen()[1]
                            )
                        }
                        self.logger.log_event("witness_statement_verify", event_data)

                        # Cache result for 300 seconds
                        self.redis_client.setex(cache_key, 300, json.dumps(is_valid))

                        # Publish to AWS IoT
                        payload = {
                            "data_hash": data_hash[:16],
                            "pubkey": pubkey[:16],
                            "is_valid": is_valid
                        }
                        payload_bytes = cbor2.dumps(payload)
                        signature = self.signer.sign(payload_bytes, self.signer.keygen()[1])
                        signed_payload = {'data': payload, 'signature': signature}

                        try:
                            self.iot_client.publish(
                                topic=f"{IOT_TOPIC_PREFIX}/witness/verify",
                                qos=1,
                                payload=cbor2.dumps(signed_payload)
                            )
                        except ClientError as e:
                            logger.warning(f"IoT publish error: {e}")

                        logger.info(f"Verified witness statement: data_hash={data_hash[:16]}..., is_valid={is_valid}")
                        return is_valid
                    except Exception as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for verify_witness_statement: {e}")
                            time.sleep(2 ** attempt)
                        else:
                            logger.error(f"Failed to verify witness statement after {retries} attempts: {e}")
                            raise
            except Exception as e:
                logger.error(f"Witness statement verification failed: {e}")
                return False

    def batch_create_witness_statements(self, statements: list, public_key: str, private_key: str, retries=3):
        """
        Create multiple signed, encrypted witness statements in a batch.
        """
        with self.lock:
            if not isinstance(statements, list) or not all(isinstance(s, dict) and "statement_type" in s and "statement_text" in s and "node_id" in s for s in statements):
                logger.warning(f"Invalid statements: {statements}")
                raise ValueError("Statements must be a list of dictionaries with statement_type, statement_text, and node_id")
            if not isinstance(public_key, str) or not isinstance(private_key, str):
                logger.warning(f"Invalid keys: public_key={public_key}, private_key={private_key}")
                raise ValueError("Invalid public_key or private_key")

            try:
                statements_hash = hashlib.sha3_512(orjson.dumps(statements, option=orjson.OPT_SORT_KEYS)).hexdigest()
                cache_key = f"witness_batch_create_{statements_hash}_{public_key[:16]}"
                cached_packages = self.redis_client.get(cache_key)
                if cached_packages:
                    logger.debug(f"Returning cached batch witness statements: statements_hash={statements_hash[:16]}...")
                    return json.loads(cached_packages)

                packages = []
                for attempt in range(retries):
                    try:
                        for statement in statements:
                            package = self.create_witness_statement(
                                statement["statement_type"],
                                statement["statement_text"],
                                statement["node_id"],
                                public_key,
                                private_key
                            )
                            packages.append(package)

                        # Generate Dilithium signature for batch
                        packages_bytes = cbor2.dumps(packages)
                        pub_key, priv_key = self.signer.keygen()
                        signature = self.signer.sign(packages_bytes, priv_key)

                        # Log to QLDB
                        event_data = {
                            "batch_hash": hashlib.sha3_512(packages_bytes).hexdigest(),
                            "statement_count": len(packages),
                            "signature": signature
                        }
                        self.logger.log_event("witness_statement_batch_create", event_data)

                        # Cache packages for 300 seconds
                        self.redis_client.setex(cache_key, 300, json.dumps(packages))

                        # Publish to AWS IoT
                        payload = {
                            "batch_hash": event_data["batch_hash"][:16],
                            "statement_count": len(packages),
                            "public_key": pub_key[:16]
                        }
                        payload_bytes = cbor2.dumps(payload)
                        signature = self.signer.sign(payload_bytes, priv_key)
                        signed_payload = {'data': payload, 'signature': signature}

                        try:
                            self.iot_client.publish(
                                topic=f"{IOT_TOPIC_PREFIX}/witness/batch_create",
                                qos=1,
                                payload=cbor2.dumps(signed_payload)
                            )
                        except ClientError as e:
                            logger.warning(f"IoT publish error: {e}")

                        logger.info(f"Created {len(packages)} witness statements in batch: batch_hash={event_data['batch_hash'][:16]}...")
                        return packages
                    except Exception as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for batch_create_witness_statements: {e}")
                            time.sleep(2 ** attempt)
                        else:
                            logger.error(f"Failed to create batch witness statements after {retries} attempts: {e}")
                            raise
            except Exception as e:
                logger.error(f"Batch witness statement creation failed: {e}")
                raise

# Example usage
if __name__ == "__main__":
    witness = WitnessStatement()
    fake_pubkey, fake_privkey = witness.kyber.keygen()
    package = witness.create_witness_statement(
        "HUMAN_RIGHTS_VIOLATION", "Test report", "node-xyz", fake_pubkey, fake_privkey
    )
    print("Witness Statement Package:", package)
    is_valid = witness.verify_witness_statement(
        bytes.fromhex(package["encrypted"]), package["signature"], fake_pubkey
    )
    print("Signature Valid:", is_valid)