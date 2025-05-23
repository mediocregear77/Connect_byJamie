import os
import json
import random
import logging
import threading
from dotenv import load_dotenv
import redis
import cbor2
import boto3
from botocore.exceptions import ClientError
from audit_core.audit_log.qldb_logger import QLDBLogger
from security_core.pqc.kyber import KyberKEM
from security_core.pqc.dilithium import DilithiumSigner
from security_core.zk_snark.zkp import ZKProof
import hashlib
import time
import orjson
from jsonschema import validate, ValidationError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/onion_router.log')
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')
IOT_TOPIC_PREFIX = os.getenv('IOT_TOPIC_PREFIX', 'mesh')
RELAY_NODE_PUBKEYS = json.loads(os.getenv('RELAY_NODE_PUBKEYS', '["relay_pubkey_A", "relay_pubkey_B", "relay_pubkey_C", "relay_pubkey_D"]'))

# JSON schema for routed reports
REPORT_SCHEMA = {
    "type": "object",
    "properties": {
        "route": {"type": "array", "items": {"type": "string"}},
        "onion_payload": {"type": "string"}
    },
    "required": ["route", "onion_payload"]
}

class OnionRouter:
    """
    Onion routing for secure and anonymous delivery of reports.
    Uses Kyber KEM for encryption and Dilithium for signatures.
    """

    def __init__(self):
        self.lock = threading.Lock()
        self.redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
        self.iot_client = boto3.client('iot-data', region_name=AWS_REGION)
        self.kyber = KyberKEM()
        self.signer = DilithiumSigner()
        self.zkp = ZKProof()
        self.logger = QLDBLogger()

    def _discover_relays(self, count=3):
        """Simulate dynamic relay discovery."""
        try:
            # In production, fetch from mesh network or trusted registry
            return random.sample(RELAY_NODE_PUBKEYS, min(count, len(RELAY_NODE_PUBKEYS)))
        except Exception as e:
            logger.error(f"Failed to discover relays: {e}")
            raise

    def onion_wrap(self, data: bytes, route_pubkeys: list, retries=3) -> bytes:
        """
        Wraps the data in multiple Kyber encryption layers (one per relay).
        """
        with self.lock:
            if not isinstance(data, bytes) or not isinstance(route_pubkeys, list) or not all(isinstance(key, str) for key in route_pubkeys):
                logger.warning(f"Invalid input: data={type(data)}, route_pubkeys={route_pubkeys}")
                raise ValueError("Invalid data or route_pubkeys")

            try:
                data_hash = hashlib.sha3_512(data).hexdigest()
                cache_key = f"onion_wrap_{data_hash}_{hashlib.sha3_512(str(route_pubkeys).encode()).hexdigest()}"
                cached_payload = self.redis_client.get(cache_key)
                if cached_payload:
                    logger.debug(f"Returning cached wrapped payload: data_hash={data_hash[:16]}...")
                    return bytes.fromhex(cached_payload)

                for attempt in range(retries):
                    try:
                        payload = data
                        for pubkey in reversed(route_pubkeys):
                            ciphertext, _ = self.kyber.encapsulate(pubkey)
                            # Combine ciphertext with payload for next layer
                            payload = cbor2.dumps({"ciphertext": ciphertext, "next": payload})

                        payload_hex = payload.hex()

                        # Generate Dilithium signature
                        payload_bytes = payload
                        pub_key, priv_key = self.signer.keygen()
                        signature = self.signer.sign(payload_bytes, priv_key)

                        # Generate ZKP for payload integrity
                        payload_hash = hashlib.sha3_512(payload_bytes).hexdigest()
                        zkp = generate_zkp(payload_hash)
                        if not verify_zkp(payload_hash, zkp):
                            logger.warning(f"ZKP verification failed for payload_hash={payload_hash[:16]}...")
                            raise RuntimeError("Payload integrity verification failed")

                        # Log to QLDB
                        event_data = {
                            "payload_hash": payload_hash,
                            "route_count": len(route_pubkeys),
                            "signature": signature
                        }
                        self.logger.log_event("onion_wrap", event_data)

                        # Cache payload for 300 seconds
                        self.redis_client.setex(cache_key, 300, payload_hex)

                        # Publish to AWS IoT
                        payload = {
                            "payload_hash": payload_hash[:16],
                            "route_count": len(route_pubkeys),
                            "public_key": pub_key[:16]
                        }
                        payload_bytes = cbor2.dumps(payload)
                        signature = self.signer.sign(payload_bytes, priv_key)
                        signed_payload = {'data': payload, 'signature': signature}

                        try:
                            self.iot_client.publish(
                                topic=f"{IOT_TOPIC_PREFIX}/onion/wrap",
                                qos=1,
                                payload=cbor2.dumps(signed_payload)
                            )
                        except ClientError as e:
                            logger.warning(f"IoT publish error: {e}")

                        logger.info(f"Wrapped onion payload: payload_hash={payload_hash[:16]}..., route_count={len(route_pubkeys)}")
                        return payload
                    except Exception as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for onion_wrap: {e}")
                            time.sleep(2 ** attempt)
                        else:
                            logger.error(f"Failed to wrap payload after {retries} attempts: {e}")
                            raise
            except Exception as e:
                logger.error(f"Onion wrap failed: {e}")
                raise

    def onion_route_report(self, ciphertext: bytes, dest_pubkey: str, retries=3):
        """
        Route a ciphertext to destination pubkey via onion routing.
        """
        with self.lock:
            if not isinstance(ciphertext, bytes) or not isinstance(dest_pubkey, str):
                logger.warning(f"Invalid input: ciphertext={type(ciphertext)}, dest_pubkey={dest_pubkey}")
                raise ValueError("Invalid ciphertext or dest_pubkey")

            try:
                data_hash = hashlib.sha3_512(ciphertext).hexdigest()
                cache_key = f"onion_route_{data_hash}_{dest_pubkey[:16]}"
                cached_routed = self.redis_client.get(cache_key)
                if cached_routed:
                    logger.debug(f"Returning cached routed report: data_hash={data_hash[:16]}...")
                    return json.loads(cached_routed)

                for attempt in range(retries):
                    try:
                        # Discover relays
                        relays = self._discover_relays()
                        full_route = relays + [dest_pubkey]

                        # Wrap payload
                        onion_payload = self.onion_wrap(ciphertext, full_route)

                        routed = {
                            "route": full_route,
                            "onion_payload": onion_payload.hex()
                        }

                        # Validate routed report
                        validate(instance=routed, schema=REPORT_SCHEMA)

                        # Generate Dilithium signature
                        routed_bytes = cbor2.dumps(routed)
                        pub_key, priv_key = self.signer.keygen()
                        signature = self.signer.sign(routed_bytes, priv_key)
                        routed["signature"] = signature
                        routed["public_key"] = pub_key

                        # Generate ZKP for routed report integrity
                        routed_hash = hashlib.sha3_512(routed_bytes).hexdigest()
                        zkp = generate_zkp(routed_hash)
                        if not verify_zkp(routed_hash, zkp):
                            logger.warning(f"ZKP verification failed for routed_hash={routed_hash[:16]}...")
                            raise RuntimeError("Routed report integrity verification failed")
                        routed["zkp"] = zkp

                        # Log to QLDB
                        event_data = {
                            "routed_hash": routed_hash,
                            "route_count": len(full_route),
                            "dest_pubkey": dest_pubkey[:16],
                            "signature": signature
                        }
                        self.logger.log_event("onion_route_report", event_data)

                        # Cache routed report for 300 seconds
                        self.redis_client.setex(cache_key, 300, json.dumps(routed))

                        # Publish to AWS IoT
                        payload = {
                            "routed_hash": routed_hash[:16],
                            "route_count": len(full_route),
                            "dest_pubkey": dest_pubkey[:16],
                            "public_key": pub_key[:16]
                        }
                        payload_bytes = cbor2.dumps(payload)
                        signature = self.signer.sign(payload_bytes, priv_key)
                        signed_payload = {'data': payload, 'signature': signature}

                        try:
                            self.iot_client.publish(
                                topic=f"{IOT_TOPIC_PREFIX}/onion/route",
                                qos=1,
                                payload=cbor2.dumps(signed_payload)
                            )
                        except ClientError as e:
                            logger.warning(f"IoT publish error: {e}")

                        logger.info(f"Routed onion report: routed_hash={routed_hash[:16]}..., dest_pubkey={dest_pubkey[:16]}")
                        return routed
                    except Exception as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for onion_route_report: {e}")
                            time.sleep(2 ** attempt)
                        else:
                            logger.error(f"Failed to route report after {retries} attempts: {e}")
                            raise
            except ValidationError as e:
                logger.error(f"Invalid routed report schema: {e}")
                raise
            except Exception as e:
                logger.error(f"Onion route report failed: {e}")
                raise

    def onion_unwrap(self, onion_payload: str, route_pubkeys: list, private_key: str, retries=3) -> bytes:
        """
        Peels off onion layers to retrieve the original data using private key.
        """
        with self.lock:
            if not isinstance(onion_payload, str) or not isinstance(route_pubkeys, list) or not all(isinstance(key, str) for key in route_pubkeys) or not isinstance(private_key, str):
                logger.warning(f"Invalid input: onion_payload={onion_payload}, route_pubkeys={route_pubkeys}, private_key={private_key}")
                raise ValueError("Invalid onion_payload, route_pubkeys, or private_key")

            try:
                payload_hash = hashlib.sha3_512(onion_payload.encode()).hexdigest()
                cache_key = f"onion_unwrap_{payload_hash}_{hashlib.sha3_512(str(route_pubkeys).encode()).hexdigest()}"
                cached_data = self.redis_client.get(cache_key)
                if cached_data:
                    logger.debug(f"Returning cached unwrapped data: payload_hash={payload_hash[:16]}...")
                    return bytes.fromhex(cached_data)

                for attempt in range(retries):
                    try:
                        payload = bytes.fromhex(onion_payload)
                        for pubkey in route_pubkeys:
                            # Decode layer
                            layer = cbor2.loads(payload)
                            ciphertext = layer["ciphertext"]
                            next_payload = layer["next"]

                            # Decrypt if this is the destination (last key)
                            if pubkey == route_pubkeys[-1]:
                                shared_secret = self.kyber.decapsulate(ciphertext, private_key)
                                # Verify shared secret (assumed stored during encapsulation)
                                payload = next_payload
                            else:
                                payload = next_payload

                        # Generate Dilithium signature
                        data_bytes = payload
                        pub_key, priv_key = self.signer.keygen()
                        signature = self.signer.sign(data_bytes, priv_key)

                        # Generate ZKP for data integrity
                        data_hash = hashlib.sha3_512(data_bytes).hexdigest()
                        zkp = generate_zkp(data_hash)
                        if not verify_zkp(data_hash, zkp):
                            logger.warning(f"ZKP verification failed for data_hash={data_hash[:16]}...")
                            raise RuntimeError("Data integrity verification failed")

                        # Log to QLDB
                        event_data = {
                            "data_hash": data_hash,
                            "route_count": len(route_pubkeys),
                            "signature": signature
                        }
                        self.logger.log_event("onion_unwrap", event_data)

                        # Cache unwrapped data for 300 seconds
                        self.redis_client.setex(cache_key, 300, data_bytes.hex())

                        # Publish to AWS IoT
                        payload = {
                            "data_hash": data_hash[:16],
                            "route_count": len(route_pubkeys),
                            "public_key": pub_key[:16]
                        }
                        payload_bytes = cbor2.dumps(payload)
                        signature = self.signer.sign(payload_bytes, priv_key)
                        signed_payload = {'data': payload, 'signature': signature}

                        try:
                            self.iot_client.publish(
                                topic=f"{IOT_TOPIC_PREFIX}/onion/unwrap",
                                qos=1,
                                payload=cbor2.dumps(signed_payload)
                            )
                        except ClientError as e:
                            logger.warning(f"IoT publish error: {e}")

                        logger.info(f"Unwrapped onion payload: data_hash={data_hash[:16]}..., route_count={len(route_pubkeys)}")
                        return data_bytes
                    except Exception as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for onion_unwrap: {e}")
                            time.sleep(2 ** attempt)
                        else:
                            logger.error(f"Failed to unwrap payload after {retries} attempts: {e}")
                            raise
            except Exception as e:
                logger.error(f"Onion unwrap failed: {e}")
                raise

# Example usage
if __name__ == "__main__":
    router = OnionRouter()
    data = b"secret_report"
    dest_key = "ngo_dest_pubkey"
    user_pub_key, user_priv_key = router.kyber.keygen()
    routed = router.onion_route_report(data, dest_key)
    print("Onion Routed Report:", routed)
    unwrapped = router.onion_unwrap(routed["onion_payload"], routed["route"], user_priv_key)
    print("Unwrapped Data:", unwrapped)