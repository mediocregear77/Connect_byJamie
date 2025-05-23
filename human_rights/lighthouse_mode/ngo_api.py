from flask import Flask, request, jsonify
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
import time
import orjson
from jsonschema import validate, ValidationError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/ngo_api.log')
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')
IOT_TOPIC_PREFIX = os.getenv('IOT_TOPIC_PREFIX', 'mesh')
KMS_KEY_ID = os.getenv('KMS_KEY_ID', '')
FLASK_HOST = os.getenv('FLASK_HOST', '0.0.0.0')
FLASK_PORT = int(os.getenv('FLASK_PORT', 9050))

# JSON schema for incoming reports
REPORT_SCHEMA = {
    "type": "object",
    "properties": {
        "statement_id": {"type": "string"},
        "encrypted": {"type": "string"},
        "signature": {"type": "string"},
        "sender_node": {"type": "string"},
        "timestamp": {"type": "number"},
        "public_key": {"type": "string"},
        "zkp": {"type": "string"}
    },
    "required": ["statement_id", "encrypted", "signature", "sender_node", "timestamp"]
}

class NGOApi:
    """
    NGO API for secure intake of Lighthouse Mode reports.
    Uses Kyber for decryption, Dilithium for verification, and zk-SNARKs for integrity.
    """

    def __init__(self):
        self.app = Flask(__name__)
        self.lock = threading.Lock()
        self.redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
        self.iot_client = boto3.client('iot-data', region_name=AWS_REGION)
        self.kms_client = boto3.client('kms', region_name=AWS_REGION)
        self.kyber = KyberKEM()
        self.signer = DilithiumSigner()
        self.zkp = ZKProof()
        self.logger = QLDBLogger()
        self.public_feed = PublicFeed()
        self._register_routes()

    def _register_routes(self):
        """Register Flask routes."""
        self.app.add_url_rule('/api/lighthouse/report', view_func=self.receive_report, methods=['POST'])
        self.app.add_url_rule('/api/lighthouse/batch_report', view_func=self.receive_batch_report, methods=['POST'])

    def _get_node_pubkey(self, node_id: str, retries=3) -> str:
        """Retrieve the public key for a node from Redis or registry."""
        with self.lock:
            try:
                cache_key = f"ngo_node_pubkey_{node_id}"
                cached_pubkey = self.redis_client.get(cache_key)
                if cached_pubkey:
                    logger.debug(f"Returning cached public key for node_id={node_id}")
                    return cached_pubkey

                for attempt in range(retries):
                    try:
                        # In production, query a secure node registry or database
                        # For demo, return NGO_PUBKEY (loaded from KMS)
                        pub_key = self.kms_client.decrypt(
                            CiphertextBlob=base64.b64decode(os.getenv('NGO_PUBKEY', 'NGO_PUBKEY_DEF')),
                            KeyId=KMS_KEY_ID,
                            EncryptionAlgorithm='SYMMETRIC_DEFAULT'
                        )['Plaintext'].decode()

                        # Cache public key for 3600 seconds
                        self.redis_client.setex(cache_key, 3600, pub_key)

                        logger.debug(f"Retrieved public key for node_id={node_id}")
                        return pub_key
                    except ClientError as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for get_node_pubkey: {e}")
                            time.sleep(2 ** attempt)
                        else:
                            logger.error(f"Failed to get node pubkey after {retries} attempts: {e}")
                            raise
            except Exception as e:
                logger.error(f"Failed to get node pubkey: {e}")
                raise

    def receive_report(self):
        """
        Endpoint for NGOs to receive a single encrypted, signed witness report.
        """
        with self.lock:
            try:
                data = request.json
                validate(instance=data, schema=REPORT_SCHEMA)

                statement_id = data["statement_id"]
                encrypted = bytes.fromhex(data["encrypted"])
                signature = data["signature"]
                sender_node = data["sender_node"]
                zkp = data.get("zkp")

                data_hash = hashlib.sha3_512(orjson.dumps(data, option=orjson.OPT_SORT_KEYS)).hexdigest()
                cache_key = f"ngo_report_{data_hash}"
                cached_response = self.redis_client.get(cache_key)
                if cached_response:
                    logger.debug(f"Returning cached report response: statement_id={statement_id}")
                    return jsonify(json.loads(cached_response))

                for attempt in range(3):
                    try:
                        # Verify ZKP
                        if zkp and not self.zkp.verify_proof(data_hash, zkp):
                            logger.warning(f"ZKP verification failed for statement_id={statement_id}")
                            return jsonify({"status": "error", "message": "ZKP verification failed"}), 403

                        # Verify signature
                        sender_pubkey = self._get_node_pubkey(sender_node)
                        if not self.signer.verify(encrypted, signature, sender_pubkey):
                            logger.warning(f"Signature verification failed for statement_id={statement_id}")
                            return jsonify({"status": "error", "message": "Signature invalid"}), 403

                        # Decrypt report
                        decrypted = self.kyber.decapsulate(encrypted, NGO_PRIVATE_KEY)
                        payload = orjson.loads(decrypted)

                        # Log to QLDB
                        qldb_event_data = {
                            "statement_id": statement_id,
                            "data_hash": data_hash,
                            "sender_node": sender_node,
                            "signature": self.signer.sign(
                                cbor2.dumps({"statement_id": statement_id}),
                                self.signer.keygen()[1]
                            )
                        }
                        self.logger.log_event("ngo_report_received", qldb_event_data)

                        # Log to public feed (anonymized)
                        public_event_data = {
                            "type": "ngo_report_received",
                            "time": int(time.time()),
                            "statement_id": statement_id,
                            "data_hash": data_hash
                        }
                        self.public_feed.publish_event("ngo_report_received", public_event_data)

                        # Publish to AWS IoT
                        payload = {
                            "statement_id": statement_id,
                            "data_hash": data_hash[:16],
                            "sender_node": sender_node
                        }
                        payload_bytes = cbor2.dumps(payload)
                        signature = self.signer.sign(payload_bytes, self.signer.keygen()[1])
                        signed_payload = {'data': payload, 'signature': signature}

                        try:
                            self.iot_client.publish(
                                topic=f"{IOT_TOPIC_PREFIX}/ngo/report",
                                qos=1,
                                payload=cbor2.dumps(signed_payload)
                            )
                        except ClientError as e:
                            logger.warning(f"IoT publish error: {e}")

                        response = {
                            "status": "success",
                            "statement_id": statement_id,
                            "report": payload
                        }

                        # Cache response for 300 seconds
                        self.redis_client.setex(cache_key, 300, json.dumps(response))

                        logger.info(f"Received NGO report: statement_id={statement_id}, data_hash={data_hash[:16]}...")
                        return jsonify(response)
                    except Exception as e:
                        if attempt < 2:
                            logger.warning(f"Retry {attempt + 1}/3 for receive_report: {e}")
                            time.sleep(2 ** attempt)
                        else:
                            logger.error(f"Failed to process report after 3 attempts: {e}")
                            return jsonify({"status": "error", "message": "Processing failed", "error": str(e)}), 500
            except ValidationError as e:
                logger.error(f"Invalid report schema: {e}")
                return jsonify({"status": "error", "message": "Invalid report format"}), 400
            except Exception as e:
                logger.error(f"NGO report processing failed: {e}")
                return jsonify({"status": "error", "message": "Internal server error", "error": str(e)}), 500

    def receive_batch_report(self):
        """
        Endpoint for NGOs to receive multiple encrypted, signed witness reports.
        """
        with self.lock:
            try:
                data = request.json
                if not isinstance(data, list) or not all(isinstance(item, dict) for item in data):
                    logger.warning(f"Invalid batch data: {data}")
                    return jsonify({"status": "error", "message": "Batch must be a list of reports"}), 400

                batch_hash = hashlib.sha3_512(orjson.dumps(data, option=orjson.OPT_SORT_KEYS)).hexdigest()
                cache_key = f"ngo_batch_report_{batch_hash}"
                cached_response = self.redis_client.get(cache_key)
                if cached_response:
                    logger.debug(f"Returning cached batch report response: batch_hash={batch_hash[:16]}...")
                    return jsonify(json.loads(cached_response))

                results = []
                for item in data:
                    validate(instance=item, schema=REPORT_SCHEMA)

                    statement_id = item["statement_id"]
                    encrypted = bytes.fromhex(item["encrypted"])
                    signature = item["signature"]
                    sender_node = item["sender_node"]
                    zkp = item.get("zkp")

                    for attempt in range(3):
                        try:
                            # Verify ZKP
                            item_hash = hashlib.sha3_512(orjson.dumps(item, option=orjson.OPT_SORT_KEYS)).hexdigest()
                            if zkp and not self.zkp.verify_proof(item_hash, zkp):
                                results.append({"statement_id": statement_id, "status": "error", "message": "ZKP verification failed"})
                                break

                            # Verify signature
                            sender_pubkey = self._get_node_pubkey(sender_node)
                            if not self.signer.verify(encrypted, signature, sender_pubkey):
                                results.append({"statement_id": statement_id, "status": "error", "message": "Signature invalid"})
                                break

                            # Decrypt report
                            decrypted = self.kyber.decapsulate(encrypted, NGO_PRIVATE_KEY)
                            payload = orjson.loads(decrypted)

                            results.append({"statement_id": statement_id, "status": "success", "report": payload})
                            break
                        except Exception as e:
                            if attempt < 2:
                                logger.warning(f"Retry {attempt + 1}/3 for batch report {statement_id}: {e}")
                                time.sleep(2 ** attempt)
                            else:
                                logger.error(f"Failed to process batch report {statement_id} after 3 attempts: {e}")
                                results.append({"statement_id": statement_id, "status": "error", "message": str(e)})

                # Log to QLDB
                qldb_event_data = {
                    "batch_hash": batch_hash,
                    "report_count": len(data),
                    "success_count": sum(1 for r in results if r["status"] == "success"),
                    "signature": self.signer.sign(
                        cbor2.dumps({"batch_hash": batch_hash}),
                        self.signer.keygen()[1]
                    )
                }
                self.logger.log_event("ngo_batch_report_received", qldb_event_data)

                # Log to public feed (anonymized)
                public_event_data = {
                    "type": "ngo_batch_report_received",
                    "time": int(time.time()),
                    "batch_hash": batch_hash,
                    "report_count": len(data)
                }
                self.public_feed.publish_event("ngo_batch_report_received", public_event_data)

                # Publish to AWS IoT
                payload = {
                    "batch_hash": batch_hash[:16],
                    "report_count": len(data),
                    "success_count": qldb_event_data["success_count"]
                }
                payload_bytes = cbor2.dumps(payload)
                signature = self.signer.sign(payload_bytes, self.signer.keygen()[1])
                signed_payload = {'data': payload, 'signature': signature}

                try:
                    self.iot_client.publish(
                        topic=f"{IOT_TOPIC_PREFIX}/ngo/batch_report",
                        qos=1,
                        payload=cbor2.dumps(signed_payload)
                    )
                except ClientError as e:
                    logger.warning(f"IoT publish error: {e}")

                response = {
                    "status": "success",
                    "batch_hash": batch_hash,
                    "results": results
                }

                # Cache response for 300 seconds
                self.redis_client.setex(cache_key, 300, json.dumps(response))

                logger.info(f"Received {len(data)} NGO batch reports: batch_hash={batch_hash[:16]}..., success={qldb_event_data['success_count']}")
                return jsonify(response)
            except ValidationError as e:
                logger.error(f"Invalid batch report schema: {e}")
                return jsonify({"status": "error", "message": "Invalid batch report format"}), 400
            except Exception as e:
                logger.error(f"NGO batch report processing failed: {e}")
                return jsonify({"status": "error", "message": "Internal server error", "error": str(e)}), 500

    def run(self):
        """Run the Flask application."""
        self.app.run(host=FLASK_HOST, port=FLASK_PORT)

# Example usage
if __name__ == "__main__":
    ngo_api = NGOApi()
    ngo_api.run()