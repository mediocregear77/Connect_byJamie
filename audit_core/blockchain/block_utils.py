import hashlib
import json
import logging
import threading
from typing import List
from dotenv import load_dotenv
import os
import redis
import cbor2
import boto3
from botocore.exceptions import ClientError
from audit_core.audit_log.qldb_logger import QLDBLogger
from security_core.pqc.dilithium import DilithiumSigner
from security_core.zk_snark.zkp import generate_zkp, verify_zkp
import orjson
import time
from jsonschema import validate, ValidationError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/block_utils.log')
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')
IOT_TOPIC_PREFIX = os.getenv('IOT_TOPIC_PREFIX', 'mesh')

# JSON schema for events
EVENT_SCHEMA = {
    "type": "object",
    "properties": {
        "event_id": {"type": "string"},
        "type": {"type": "string"},
        "timestamp": {"type": "string"},
        "data": {"type": ["object", "string"]},
        "signature": {"type": "string"},
        "public_key": {"type": "string"},
        "zkp": {"type": "string"}
    },
    "required": ["event_id"]
}

class BlockUtils:
    """
    Blockchain utility functions for audit event processing with PQC signatures.
    Supports encoding, hashing, Merkle tree construction, and block parsing.
    """

    def __init__(self):
        self.lock = threading.Lock()
        self.redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
        self.iot_client = boto3.client('iot-data', region_name=AWS_REGION)
        self.signer = DilithiumSigner()
        self.logger = QLDBLogger()

    def encode_event(self, event: dict, retries=3) -> str:
        """
        Encode an event dictionary as a canonical JSON string for hashing/storage.
        """
        with self.lock:
            if not isinstance(event, dict):
                logger.warning(f"Invalid event: {event}")
                raise ValueError("Event must be a dictionary")

            try:
                validate(instance=event, schema=EVENT_SCHEMA)

                event_hash = hashlib.sha3_512(orjson.dumps(event, option=orjson.OPT_SORT_KEYS)).hexdigest()
                cache_key = f"block_utils_encode_{event_hash}"
                cached_encoded = self.redis_client.get(cache_key)
                if cached_encoded:
                    logger.debug(f"Returning cached encoded event: event_hash={event_hash[:16]}...")
                    return cached_encoded

                for attempt in range(retries):
                    try:
                        canonical = orjson.dumps(event, option=orjson.OPT_SORT_KEYS).decode()

                        # Generate Dilithium signature
                        canonical_bytes = canonical.encode('utf-8')
                        pub_key, priv_key = self.signer.keygen()
                        signature = self.signer.sign(canonical_bytes, priv_key)

                        # Log to QLDB
                        event_data = {
                            "event_hash": event_hash,
                            "event_id": event.get("event_id", "unknown"),
                            "signature": signature
                        }
                        self.logger.log_event("block_utils_encode", event_data)

                        # Cache encoded event for 300 seconds
                        self.redis_client.setex(cache_key, 300, canonical)

                        # Publish to AWS IoT
                        payload = {
                            "event_hash": event_hash,
                            "event_id": event.get("event_id", "unknown"),
                            "public_key": pub_key[:16]
                        }
                        payload_bytes = cbor2.dumps(payload)
                        signature = self.signer.sign(payload_bytes, priv_key)
                        signed_payload = {'data': payload, 'signature': signature}

                        try:
                            self.iot_client.publish(
                                topic=f"{IOT_TOPIC_PREFIX}/block_utils/encode",
                                qos=1,
                                payload=cbor2.dumps(signed_payload)
                            )
                        except ClientError as e:
                            logger.warning(f"IoT publish error: {e}")

                        logger.debug(f"Encoded event: event_id={event.get('event_id', 'unknown')}")
                        return canonical
                    except Exception as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for encode_event: {e}")
                            time.sleep(2 ** attempt)
                        else:
                            logger.error(f"Failed to encode event after {retries} attempts: {e}")
                            raise
            except ValidationError as e:
                logger.error(f"Invalid event schema: {e}")
                raise
            except Exception as e:
                logger.error(f"Failed to encode event: {e}")
                raise

    def hash_event(self, event: dict, retries=3) -> str:
        """
        Calculate the SHA3-512 hash of an event for blockchain anchoring.
        """
        with self.lock:
            if not isinstance(event, dict):
                logger.warning(f"Invalid event: {event}")
                raise ValueError("Event must be a dictionary")

            try:
                validate(instance=event, schema=EVENT_SCHEMA)

                event_bytes = orjson.dumps(event, option=orjson.OPT_SORT_KEYS)
                event_hash = hashlib.sha3_512(event_bytes).hexdigest()
                cache_key = f"block_utils_hash_{event_hash}"
                cached_hash = self.redis_client.get(cache_key)
                if cached_hash:
                    logger.debug(f"Returning cached event hash: event_hash={event_hash[:16]}...")
                    return cached_hash

                for attempt in range(retries):
                    try:
                        canonical = self.encode_event(event)
                        hash_value = hashlib.sha3_512(canonical.encode('utf-8')).hexdigest()

                        # Generate Dilithium signature
                        hash_bytes = hash_value.encode('utf-8')
                        pub_key, priv_key = self.signer.keygen()
                        signature = self.signer.sign(hash_bytes, priv_key)

                        # Generate ZKP for hash integrity
                        zkp = generate_zkp(hash_value)
                        if not verify_zkp(hash_value, zkp):
                            logger.warning(f"ZKP verification failed for hash={hash_value[:16]}...")
                            raise RuntimeError("Hash integrity verification failed")

                        # Log to QLDB
                        event_data = {
                            "event_hash": hash_value,
                            "event_id": event.get("event_id", "unknown"),
                            "signature": signature
                        }
                        self.logger.log_event("block_utils_hash", event_data)

                        # Cache hash for 300 seconds
                        self.redis_client.setex(cache_key, 300, hash_value)

                        # Publish to AWS IoT
                        payload = {
                            "event_hash": hash_value[:16],
                            "event_id": event.get("event_id", "unknown"),
                            "public_key": pub_key[:16]
                        }
                        payload_bytes = cbor2.dumps(payload)
                        signature = self.signer.sign(payload_bytes, priv_key)
                        signed_payload = {'data': payload, 'signature': signature}

                        try:
                            self.iot_client.publish(
                                topic=f"{IOT_TOPIC_PREFIX}/block_utils/hash",
                                qos=1,
                                payload=cbor2.dumps(signed_payload)
                            )
                        except ClientError as e:
                            logger.warning(f"IoT publish error: {e}")

                        logger.debug(f"Hashed event: event_id={event.get('event_id', 'unknown')}, hash={hash_value[:16]}...")
                        return hash_value
                    except Exception as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for hash_event: {e}")
                            time.sleep(2 ** attempt)
                        else:
                            logger.error(f"Failed to hash event after {retries} attempts: {e}")
                            raise
            except ValidationError as e:
                logger.error(f"Invalid event schema: {e}")
                raise
            except Exception as e:
                logger.error(f"Failed to hash event: {e}")
                raise

    def calc_merkle_root(self, event_hashes: List[str], retries=3) -> str:
        """
        Calculate the Merkle root of a list of event hashes.
        """
        with self.lock:
            if not isinstance(event_hashes, list) or not all(isinstance(h, str) for h in event_hashes):
                logger.warning(f"Invalid event hashes: {event_hashes}")
                raise ValueError("Event hashes must be a list of strings")
            if not event_hashes:
                return ''

            try:
                hashes_hash = hashlib.sha3_512(cbor2.dumps(event_hashes)).hexdigest()
                cache_key = f"block_utils_merkle_root_{hashes_hash}"
                cached_root = self.redis_client.get(cache_key)
                if cached_root:
                    logger.debug(f"Returning cached Merkle root: hashes_hash={hashes_hash[:16]}...")
                    return cached_root

                for attempt in range(retries):
                    try:
                        current = event_hashes
                        while len(current) > 1:
                            next_level = []
                            for i in range(0, len(current), 2):
                                left = current[i]
                                right = current[i + 1] if i + 1 < len(current) else left
                                combined = hashlib.sha3_512((left + right).encode('utf-8')).hexdigest()
                                next_level.append(combined)
                            current = next_level
                        root = current[0]

                        # Generate Dilithium signature
                        root_bytes = root.encode('utf-8')
                        pub_key, priv_key = self.signer.keygen()
                        signature = self.signer.sign(root_bytes, priv_key)

                        # Generate ZKP for root integrity
                        zkp = generate_zkp(root)
                        if not verify_zkp(root, zkp):
                            logger.warning(f"ZKP verification failed for root={root[:16]}...")
                            raise RuntimeError("Merkle root integrity verification failed")

                        # Log to QLDB
                        event_data = {
                            "root_hash": root,
                            "hash_count": len(event_hashes),
                            "signature": signature
                        }
                        self.logger.log_event("block_utils_merkle_root", event_data)

                        # Cache root for 300 seconds
                        self.redis_client.setex(cache_key, 300, root)

                        # Publish to AWS IoT
                        payload = {
                            "root_hash": root[:16],
                            "hash_count": len(event_hashes),
                            "public_key": pub_key[:16]
                        }
                        payload_bytes = cbor2.dumps(payload)
                        signature = self.signer.sign(payload_bytes, priv_key)
                        signed_payload = {'data': payload, 'signature': signature}

                        try:
                            self.iot_client.publish(
                                topic=f"{IOT_TOPIC_PREFIX}/block_utils/merkle_root",
                                qos=1,
                                payload=cbor2.dumps(signed_payload)
                            )
                        except ClientError as e:
                            logger.warning(f"IoT publish error: {e}")

                        logger.info(f"Calculated Merkle root: root={root[:16]}..., hashes={len(event_hashes)}")
                        return root
                    except Exception as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for calc_merkle_root: {e}")
                            time.sleep(2 ** attempt)
                        else:
                            logger.error(f"Failed to calculate Merkle root after {retries} attempts: {e}")
                            raise
            except Exception as e:
                logger.error(f"Failed to calculate Merkle root: {e}")
                raise

    def validate_merkle_branch(self, leaf_hash: str, branch: List[str], root: str, retries=3) -> bool:
        """
        Verify that a leaf_hash belongs to a given Merkle root via the provided branch.
        """
        with self.lock:
            if not isinstance(leaf_hash, str) or not isinstance(branch, list) or not all(isinstance(s, str) for s in branch) or not isinstance(root, str):
                logger.warning(f"Invalid input: leaf_hash={leaf_hash}, branch={branch}, root={root}")
                raise ValueError("Invalid leaf_hash, branch, or root")

            try:
                branch_hash = hashlib.sha3_512(cbor2.dumps(branch)).hexdigest()
                cache_key = f"block_utils_merkle_branch_{leaf_hash}_{branch_hash}"
                cached_result = self.redis_client.get(cache_key)
                if cached_result:
                    logger.debug(f"Returning cached Merkle branch validation: branch_hash={branch_hash[:16]}...")
                    return json.loads(cached_result)

                for attempt in range(retries):
                    try:
                        computed = leaf_hash
                        for sibling in branch:
                            combined = ''.join(sorted([computed, sibling]))
                            computed = hashlib.sha3_512(combined.encode('utf-8')).hexdigest()
                        is_valid = computed == root

                        # Generate Dilithium signature
                        result_bytes = cbor2.dumps({"is_valid": is_valid})
                        pub_key, priv_key = self.signer.keygen()
                        signature = self.signer.sign(result_bytes, priv_key)

                        # Log to QLDB
                        event_data = {
                            "leaf_hash": leaf_hash[:16],
                            "root_hash": root[:16],
                            "is_valid": is_valid,
                            "signature": signature
                        }
                        self.logger.log_event("block_utils_merkle_branch", event_data)

                        # Cache result for 300 seconds
                        self.redis_client.setex(cache_key, 300, json.dumps(is_valid))

                        # Publish to AWS IoT
                        payload = {
                            "leaf_hash": leaf_hash[:16],
                            "root_hash": root[:16],
                            "is_valid": is_valid,
                            "public_key": pub_key[:16]
                        }
                        payload_bytes = cbor2.dumps(payload)
                        signature = self.signer.sign(payload_bytes, priv_key)
                        signed_payload = {'data': payload, 'signature': signature}

                        try:
                            self.iot_client.publish(
                                topic=f"{IOT_TOPIC_PREFIX}/block_utils/merkle_branch",
                                qos=1,
                                payload=cbor2.dumps(signed_payload)
                            )
                        except ClientError as e:
                            logger.warning(f"IoT publish error: {e}")

                        logger.info(f"Validated Merkle branch: leaf_hash={leaf_hash[:16]}..., is_valid={is_valid}")
                        return is_valid
                    except Exception as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for validate_merkle_branch: {e}")
                            time.sleep(2 ** attempt)
                        else:
                            logger.error(f"Failed to validate Merkle branch after {retries} attempts: {e}")
                            raise
            except Exception as e:
                logger.error(f"Failed to validate Merkle branch: {e}")
                raise

    def parse_block(self, block_data: str, retries=3) -> dict:
        """
        Parse a raw blockchain block (as JSON string) into a dict.
        """
        with self.lock:
            if not isinstance(block_data, str) or not block_data.strip():
                logger.warning(f"Invalid block_data: {block_data}")
                raise ValueError("Invalid block_data")

            try:
                block_hash = hashlib.sha3_512(block_data.encode()).hexdigest()
                cache_key = f"block_utils_parse_{block_hash}"
                cached_block = self.redis_client.get(cache_key)
                if cached_block:
                    logger.debug(f"Returning cached parsed block: block_hash={block_hash[:16]}...")
                    return json.loads(cached_block)

                for attempt in range(retries):
                    try:
                        block = orjson.loads(block_data)

                        # Generate Dilithium signature
                        block_bytes = cbor2.dumps(block)
                        pub_key, priv_key = self.signer.keygen()
                        signature = self.signer.sign(block_bytes, priv_key)

                        # Generate ZKP for block integrity
                        block_hash = hashlib.sha3_512(block_bytes).hexdigest()
                        zkp = generate_zkp(block_hash)
                        if not verify_zkp(block_hash, zkp):
                            logger.warning(f"ZKP verification failed for block_hash={block_hash[:16]}...")
                            raise RuntimeError("Block integrity verification failed")

                        # Log to QLDB
                        event_data = {
                            "block_hash": block_hash,
                            "signature": signature
                        }
                        self.logger.log_event("block_utils_parse", event_data)

                        # Cache parsed block for 300 seconds
                        self.redis_client.setex(cache_key, 300, json.dumps(block))

                        # Publish to AWS IoT
                        payload = {
                            "block_hash": block_hash[:16],
                            "public_key": pub_key[:16]
                        }
                        payload_bytes = cbor2.dumps(payload)
                        signature = self.signer.sign(payload_bytes, priv_key)
                        signed_payload = {'data': payload, 'signature': signature}

                        try:
                            self.iot_client.publish(
                                topic=f"{IOT_TOPIC_PREFIX}/block_utils/parse",
                                qos=1,
                                payload=cbor2.dumps(signed_payload)
                            )
                        except ClientError as e:
                            logger.warning(f"IoT publish error: {e}")

                        logger.info(f"Parsed block: block_hash={block_hash[:16]}...")
                        return block
                    except Exception as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for parse_block: {e}")
                            time.sleep(2 ** attempt)
                        else:
                            logger.error(f"Failed to parse block after {retries} attempts: {e}")
                            return {}
            except Exception as e:
                logger.error(f"Failed to parse block: {e}")
                return {}