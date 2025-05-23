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
        logging.FileHandler('logs/witness_verifier.log')
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')
IOT_TOPIC_PREFIX = os.getenv('IOT_TOPIC_PREFIX', 'mesh')
KMS_KEY_ID = os.getenv('KMS_KEY_ID', '')
TIMESTAMP_TOLERANCE = int(os.getenv('TIMESTAMP_TOLERANCE', 300))  # 5 minutes

# JSON schema for witness statements
STATEMENT_SCHEMA = {
    "type": "object",
    "properties": {
        "statement_id": {"type": "string"},
        "report": {"type": "object"},
        "signature": {"type": "string"},
        "sender_node": {"type": "string"},
        "timestamp": {"type": "number"},
        "public_key": {"type": "string"},
        "zkp": {"type": ["object", "string", "null"]}
    },
    "required": ["statement_id", "report", "signature", "sender_node", "timestamp"]
}

class WitnessVerifier:
    """
    Validates and attests witness statements for Lighthouse Mode.
    Integrates with Dilithium signatures, zk-SNARKs, and AWS services.
    """

    def __init__(self, node_registry=None):
        """
        node_registry: function or object for resolving node_id to public key.
        If None, uses KMS-based registry.
        """
        self.lock = threading.Lock()
        self.redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
        self.iot_client = boto3.client('iot-data', region_name=AWS_REGION)
        self.kms_client = boto3.client('kms', region_name=AWS_REGION)
        self.signer = DilithiumSigner()
        self.zkp = ZKProof()
        self.logger = QLDBLogger()
        self.public_feed = PublicFeed()
        self.node_registry = node_registry or self._default_registry

    def _default_registry(self, node_id: str, retries=3) -> str:
        """Default node registry using KMS for public key lookup."""
        try:
            cache_key = f"verifier_node_pubkey_{node_id}"
            cached_pubkey = self.redis_client.get(cache_key)
            if cached_pubkey:
                logger.debug(f"Returning cached public key for node_id={node_id}")
                return cached_pubkey

            for attempt in range(retries):
                try:
                    # In production, query a secure node registry or database
                    # For demo, assume pubkey stored in KMS
                    pub_key = self.kms_client.decrypt(
                        CiphertextBlob=base64.b64decode(os.getenv('NGO_PUBKEY', 'NGO_PUBKEY_DEF')),
                        KeyId=KMS_KEY_ID,
                        EncryptionAlgorithm='SYMMETRIC_DEFAULT'
                    )['Plaintext'].decode()

                    # Cache public key for 3600 seconds
                    self.redis_client.setex(cache_key, 3600, pub_key)
                    return pub_key
                except ClientError as e:
                    if attempt < retries - 1:
                        logger.warning(f"Retry {attempt + 1}/{retries} for node registry lookup: {e}")
                        time.sleep(2 ** attempt)
                    else:
                        logger.error(f"Failed to retrieve node pubkey after {retries} attempts: {e}")
                        raise
        except Exception as e:
            logger.error(f"Node registry lookup failed for node_id={node_id}: {e}")
            return None

    def verify_statement(self, statement: dict, retries=3) -> tuple:
        """
        Verify a witness statement.
        :param statement: dict with fields: statement_id, report, signature, sender_node, timestamp, zkp (optional)
        :return: (bool, str) tuple (valid, error_message)
        """
        with self.lock:
            try:
                validate(instance=statement, schema=STATEMENT_SCHEMA)

                statement_id = statement["statement_id"]
                data_hash = hashlib.sha3_512(orjson.dumps(statement, option=orjson.OPT_SORT_KEYS)).hexdigest()
                cache_key = f"verifier_statement_{data_hash}"
                cached_result = self.redis_client.get(cache_key)
                if cached_result:
                    logger.debug(f"Returning cached verification result: statement_id={statement_id}")
                    valid, message = json.loads(cached_result)
                    return valid, message

                for attempt in range(retries):
                    try:
                        # Check timestamp freshness
                        now = int(time.time())
                        timestamp = statement.get("timestamp", 0)
                        if abs(now - timestamp) > TIMESTAMP_TOLERANCE:
                            logger.warning(f"Timestamp out of bounds for statement_id={statement_id}: {timestamp}")
                            return False, "Timestamp out of bounds"

                        # Resolve sender public key
                        sender = statement.get("sender_node")
                        pubkey = statement.get("public_key") or self.node_registry.get(sender)
                        if not pubkey:
                            logger.warning(f"Unknown sender node for statement_id={statement_id}: {sender}")
                            return False, "Unknown sender node"

                        # Verify signature
                        msg = (orjson.dumps(statement["report"], option=orjson.OPT_SORT_KEYS).decode() + str(timestamp)).encode()
                        try:
                            signature = statement["signature"]
                        except Exception:
                            logger.warning(f"Invalid signature encoding for statement_id={statement_id}")
                            return False, "Invalid signature encoding"

                        if not self.signer.verify(msg, signature, pubkey):
                            logger.warning(f"Signature verification failed for statement_id={statement_id}")
                            return False, "Signature verification failed"

                        # Verify ZKP if present
                        if "zkp" in statement and statement["zkp"]:
                            zkp = statement["zkp"]
                            report_hash = hashlib.sha3_512(orjson.dumps(statement["report"], option=orjson.OPT_SORT_KEYS)).hexdigest()
                            if not self.zkp.verify_proof(report_hash, zkp):
                                logger.warning(f"ZKP verification failed for statement_id={statement_id}")
                                return False, "ZKP verification failed"

                        # Log to QLDB
                        qldb_event_data = {
                            "statement_id": statement_id,
                            "data_hash": data_hash,
                            "sender_node": sender,
                            "is_valid": True,
                            "signature": self.signer.sign(
                                cbor2.dumps({"statement_id": statement_id, "is_valid": True}),
                                self.signer.keygen()[1]
                            )
                        }
                        self.logger.log_event("witness_statement_verified", qldb_event_data)

                        # Log to public feed (anonymized)
                        public_event_data = {
                            "type": "witness_statement_verified",
                            "time": int(time.time()),
                            "statement_id": statement_id,
                            "data_hash": data_hash
                        }
                        self.public_feed.publish_event("witness_statement_verified", public_event_data)

                        # Publish to AWS IoT
                        payload = {
                            "statement_id": statement_id,
                            "data_hash": data_hash[:16],
                            "sender_node": sender,
                            "is_valid": True
                        }
                        payload_bytes = cbor2.dumps(payload)
                        signature = self.signer.sign(payload_bytes, self.signer.keygen()[1])
                        signed_payload = {'data': payload, 'signature': signature}

                        try:
                            self.iot_client.publish(
                                topic=f"{IOT_TOPIC_PREFIX}/verifier/statement",
                                qos=1,
                                payload=cbor2.dumps(signed_payload)
                            )
                        except ClientError as e:
                            logger.warning(f"IoT publish error: {e}")

                        result = (True, "Verified")

                        # Cache result for 300 seconds
                        self.redis_client.setex(cache_key, 300, json.dumps(result))

                        logger.info(f"Verified witness statement: statement_id={statement_id}, data_hash={data_hash[:16]}...")
                        return result
                    except Exception as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for verify_statement: {e}")
                            time.sleep(2 ** attempt)
                        else:
                            logger.error(f"Failed to verify statement after {retries} attempts: {e}")
                            return False, f"Verification failed: {str(e)}"
            except ValidationError as e:
                logger.error(f"Invalid statement schema for statement_id={statement.get('statement_id', 'unknown')}: {e}")
                return False, "Invalid statement format"
            except Exception as e:
                logger.error(f"Witness statement verification failed: {e}")
                return False, f"Internal error: {str(e)}"

    def batch_verify_statements(self, statements: list, retries=3) -> list:
        """
        Verify multiple witness statements in a batch.
        :param statements: list of statement dicts
        :return: list of (bool, str) tuples (valid, error_message)
        """
        with self.lock:
            if not isinstance(statements, list) or not all(isinstance(s, dict) for s in statements):
                logger.warning(f"Invalid statements: {statements}")
                raise ValueError("Statements must be a list of dictionaries")

            try:
                batch_hash = hashlib.sha3_512(orjson.dumps(statements, option=orjson.OPT_SORT_KEYS)).hexdigest()
                cache_key = f"verifier_batch_{batch_hash}"
                cached_results = self.redis_client.get(cache_key)
                if cached_results:
                    logger.debug(f"Returning cached batch verification results: batch_hash={batch_hash[:16]}...")
                    return json.loads(cached_results)

                results = []
                for statement in statements:
                    valid, message = self.verify_statement(statement)
                    results.append({"statement_id": statement.get("statement_id", "unknown"), "valid": valid, "message": message})

                # Log to QLDB
                qldb_event_data = {
                    "batch_hash": batch_hash,
                    "statement_count": len(statements),
                    "valid_count": sum(1 for r in results if r["valid"]),
                    "signature": self.signer.sign(
                        cbor2.dumps({"batch_hash": batch_hash}),
                        self.signer.keygen()[1]
                    )
                }
                self.logger.log_event("witness_statement_batch_verified", qldb_event_data)

                # Log to public feed (anonymized)
                public_event_data = {
                    "type": "witness_statement_batch_verified",
                    "time": int(time.time()),
                    "batch_hash": batch_hash,
                    "statement_count": len(statements),
                    "valid_count": qldb_event_data["valid_count"]
                }
                self.public_feed.publish_event("witness_statement_batch_verified", public_event_data)

                # Publish to AWS IoT
                payload = {
                    "batch_hash": batch_hash[:16],
                    "statement_count": len(statements),
                    "valid_count": qldb_event_data["valid_count"]
                }
                payload_bytes = cbor2.dumps(payload)
                signature = self.signer.sign(payload_bytes, self.signer.keygen()[1])
                signed_payload = {'data': payload, 'signature': signature}

                try:
                    self.iot_client.publish(
                        topic=f"{IOT_TOPIC_PREFIX}/verifier/batch_statement",
                        qos=1,
                        payload=cbor2.dumps(signed_payload)
                    )
                except ClientError as e:
                    logger.warning(f"IoT publish error: {e}")

                # Cache results for 300 seconds
                self.redis_client.setex(cache_key, 300, json.dumps(results))

                logger.info(f"Batch verified {len(statements)} witness statements: batch_hash={batch_hash[:16]}..., valid={qldb_event_data['valid_count']}")
                return results
            except Exception as e:
                logger.error(f"Batch witness statement verification failed: {e}")
                raise

# Example usage
if __name__ == "__main__":
    class DummyRegistry:
        def __init__(self, pubkey):
            self.pubkey = pubkey
        def get(self, node_id):
            return self.pubkey

    dummy_registry = DummyRegistry("NGO_PUBKEY_DEF")
    verifier = WitnessVerifier(dummy_registry)
    statement = {
        "statement_id": "stmt123",
        "report": {"event": "Human Rights Violation", "details": "Test"},
        "signature": "deadbeef" * 16,
        "sender_node": "node42",
        "timestamp": int(time.time()),
        "public_key": "NGO_PUBKEY_DEF"
    }
    valid, msg = verifier.verify_statement(statement)
    print("Valid:", valid, "| Message:", msg)
    batch_results = verifier.batch_verify_statements([statement])
    print("Batch Results:", batch_results)