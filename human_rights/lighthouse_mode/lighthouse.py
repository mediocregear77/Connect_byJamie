import os
import time
import logging
import threading
from dotenv import load_dotenv
import redis
import cbor2
import boto3
from botocore.exceptions import ClientError
from audit_core.audit_log.qldb_logger import QLDBLogger
from audit_core.audit_log.public_feed import PublicFeed
from security_core.pqc.kyber import KyberKEM
from security_core.pqc.dilithium import DilithiumSigner
from security_core.zk_snark.zkp import ZKProof
from human_rights.lighthouse_mode.onion_router import onion_route_report
from human_rights.lighthouse_mode.witness_statement import create_witness_statement
import hashlib
import orjson
from jsonschema import validate, ValidationError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/lighthouse.log')
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')
IOT_TOPIC_PREFIX = os.getenv('IOT_TOPIC_PREFIX', 'mesh')
LIGHTHOUSE_QUEUE_KEY = os.getenv('LIGHTHOUSE_QUEUE_KEY', 'lighthouse_reports')

# JSON schema for reports
REPORT_SCHEMA = {
    "type": "object",
    "properties": {
        "abuse": {"type": "string"},
        "location": {"type": "string"},
        "timestamp": {"type": "number"},
        "details": {"type": ["object", "string"]}
    },
    "required": ["abuse", "location", "timestamp"]
}

class Lighthouse:
    """
    Lighthouse Mode protocol for secure whistleblower and human rights reporting.
    Integrates with Kyber, Dilithium, zk-SNARKs, and onion routing for privacy.
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

    def submit_lighthouse_report(self, report: dict, user_pubkey: str, ngo_pubkeys: list, retries=3):
        """
        Securely submit a whistleblower report via Lighthouse Mode.
        :param report: dict of report details
        :param user_pubkey: reporter's ephemeral public key
        :param ngo_pubkeys: list of NGO public keys for broadcast
        """
        with self.lock:
            if not isinstance(report, dict) or not isinstance(user_pubkey, str) or not isinstance(ngo_pubkeys, list) or not all(isinstance(key, str) for key in ngo_pubkeys):
                logger.warning(f"Invalid input: report={report}, user_pubkey={user_pubkey}, ngo_pubkeys={ngo_pubkeys}")
                raise ValueError("Invalid report, user_pubkey, or ngo_pubkeys")

            try:
                validate(instance=report, schema=REPORT_SCHEMA)

                report_hash = hashlib.sha3_512(orjson.dumps(report, option=orjson.OPT_SORT_KEYS)).hexdigest()
                cache_key = f"lighthouse_report_{report_hash}_{user_pubkey[:16]}"
                cached_result = self.redis_client.get(cache_key)
                if cached_result:
                    logger.debug(f"Returning cached report submission: report_hash={report_hash[:16]}...")
                    return json.loads(cached_result)

                for attempt in range(retries):
                    try:
                        # Encrypt report using Kyber for each NGO
                        encrypted_reports = []
                        for ngo_key in ngo_pubkeys:
                            ciphertext, shared_secret = self.kyber.encapsulate(ngo_key)
                            encrypted_reports.append({
                                "ngo_key": ngo_key,
                                "ciphertext": ciphertext,
                                "shared_secret": shared_secret
                            })

                        # Generate zk-SNARK proof of authenticity/anonymity
                        zkp_statement = f"report_hash:{report_hash},pubkey:{user_pubkey}"
                        zkp_witness = f"secret:{report_hash}"
                        zkp_receipt = self.zkp.generate_proof(zkp_statement, zkp_witness)

                        # Onion-route reports for global delivery
                        routed_reports = []
                        for enc in encrypted_reports:
                            routed = onion_route_report(enc["ciphertext"], dest_pubkey=enc["ngo_key"])
                            routed_reports.append({
                                "onion": routed,
                                "ngo_key": enc["ngo_key"],
                                "shared_secret": enc["shared_secret"]
                            })

                        # Store in Redis queue for offline relay
                        queue_entry = {
                            "reports": routed_reports,
                            "zkp": zkp_receipt,
                            "timestamp": int(time.time())
                        }
                        self.redis_client.rpush(LIGHTHOUSE_QUEUE_KEY, cbor2.dumps(queue_entry))

                        # Generate Dilithium signature for event
                        event_data = {
                            "type": "lighthouse_report_submitted",
                            "time": int(time.time()),
                            "status": "encrypted",
                            "zkp": zkp_receipt,
                            "report_hash": report_hash
                        }
                        event_bytes = cbor2.dumps(event_data)
                        pub_key, priv_key = self.signer.keygen()
                        signature = self.signer.sign(event_bytes, priv_key)
                        event_data["signature"] = signature
                        event_data["public_key"] = pub_key

                        # Log to QLDB
                        qldb_event_data = {
                            "report_hash": report_hash,
                            "user_pubkey": user_pubkey[:16],
                            "ngo_count": len(ngo_pubkeys),
                            "signature": signature
                        }
                        self.logger.log_event("lighthouse_report", qldb_event_data)

                        # Log to public feed (anonymized)
                        self.public_feed.publish_event("lighthouse_report_submitted", event_data)

                        # Publish to AWS IoT
                        payload = {
                            "report_hash": report_hash,
                            "user_pubkey": user_pubkey[:16],
                            "ngo_count": len(ngo_pubkeys),
                            "public_key": pub_key[:16]
                        }
                        payload_bytes = cbor2.dumps(payload)
                        signature = self.signer.sign(payload_bytes, priv_key)
                        signed_payload = {'data': payload, 'signature': signature}

                        try:
                            self.iot_client.publish(
                                topic=f"{IOT_TOPIC_PREFIX}/lighthouse/report",
                                qos=1,
                                payload=cbor2.dumps(signed_payload)
                            )
                        except ClientError as e:
                            logger.warning(f"IoT publish error: {e}")

                        result = {"status": "submitted", "zkp": zkp_receipt, "report_hash": report_hash}

                        # Cache result for 300 seconds
                        self.redis_client.setex(cache_key, 300, json.dumps(result))

                        logger.info(f"Submitted Lighthouse report: report_hash={report_hash[:16]}..., ngo_count={len(ngo_pubkeys)}")
                        return result
                    except ClientError as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for submit_lighthouse_report: {e}")
                            time.sleep(2 ** attempt)
                        else:
                            logger.error(f"Failed to submit report after {retries} attempts: {e}")
                            raise
            except ValidationError as e:
                logger.error(f"Invalid report schema: {e}")
                raise
            except Exception as e:
                logger.error(f"Lighthouse report submission failed: {e}")
                raise

    def process_local_reports(self, retries=3):
        """
        Attempt to forward locally stored Lighthouse reports for disconnected nodes.
        """
        with self.lock:
            try:
                cache_key = f"lighthouse_process_reports_{int(time.time() // 3600)}"  # Cache per hour
                cached_result = self.redis_client.get(cache_key)
                if cached_result:
                    logger.debug(f"Skipping processing: recently processed reports")
                    return json.loads(cached_result)

                processed_reports = []
                for attempt in range(retries):
                    try:
                        # Retrieve reports from Redis queue
                        reports = []
                        while True:
                            report_data = self.redis_client.lpop(LIGHTHOUSE_QUEUE_KEY)
                            if not report_data:
                                break
                            reports.append(cbor2.loads(report_data))

                        for report in reports:
                            # Simulate mesh/satellite uplink (in production, integrate with mesh_core/mesh_node)
                            for routed in report["reports"]:
                                # Mock uplink: log and assume delivery
                                uplink_success = True  # Replace with actual uplink logic
                                if uplink_success:
                                    processed_reports.append({
                                        "onion": routed["onion"],
                                        "ngo_key": routed["ngo_key"],
                                        "timestamp": report["timestamp"]
                                    })

                        # Log to QLDB
                        qldb_event_data = {
                            "processed_count": len(processed_reports),
                            "timestamp": int(time.time()),
                            "signature": self.signer.sign(
                                cbor2.dumps({"processed_count": len(processed_reports)}),
                                self.signer.keygen()[1]
                            )
                        }
                        self.logger.log_event("lighthouse_process_reports", qldb_event_data)

                        # Publish to AWS IoT
                        payload = {
                            "processed_count": len(processed_reports),
                            "timestamp": int(time.time())
                        }
                        payload_bytes = cbor2.dumps(payload)
                        signature = self.signer.sign(payload_bytes, self.signer.keygen()[1])
                        signed_payload = {'data': payload, 'signature': signature}

                        try:
                            self.iot_client.publish(
                                topic=f"{IOT_TOPIC_PREFIX}/lighthouse/process",
                                qos=1,
                                payload=cbor2.dumps(signed_payload)
                            )
                        except ClientError as e:
                            logger.warning(f"IoT publish error: {e}")

                        # Cache result for 3600 seconds
                        self.redis_client.setex(cache_key, 3600, json.dumps(processed_reports))

                        logger.info(f"Processed {len(processed_reports)} Lighthouse reports")
                        return processed_reports
                    except ClientError as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for process_local_reports: {e}")
                            time.sleep(2 ** attempt)
                        else:
                            logger.error(f"Failed to process reports after {retries} attempts: {e}")
                            raise
            except Exception as e:
                logger.error(f"Failed to process local reports: {e}")
                raise

    def submit_witness_statement(self, statement_data: dict, verifier_pubkey: str, retries=3):
        """
        Submit a pre-defined witness statement for urgent human rights alert.
        """
        with self.lock:
            if not isinstance(statement_data, dict) or not isinstance(verifier_pubkey, str):
                logger.warning(f"Invalid input: statement_data={statement_data}, verifier_pubkey={verifier_pubkey}")
                raise ValueError("Invalid statement_data or verifier_pubkey")

            try:
                statement_hash = hashlib.sha3_512(orjson.dumps(statement_data, option=orjson.OPT_SORT_KEYS)).hexdigest()
                cache_key = f"lighthouse_statement_{statement_hash}_{verifier_pubkey[:16]}"
                cached_statement = self.redis_client.get(cache_key)
                if cached_statement:
                    logger.debug(f"Returning cached witness statement: statement_hash={statement_hash[:16]}...")
                    return json.loads(cached_statement)

                for attempt in range(retries):
                    try:
                        statement = create_witness_statement(statement_data, verifier_pubkey)

                        # Generate Dilithium signature
                        statement_bytes = cbor2.dumps(statement)
                        pub_key, priv_key = self.signer.keygen()
                        signature = self.signer.sign(statement_bytes, priv_key)
                        statement["signature"] = signature
                        statement["public_key"] = pub_key

                        # Generate ZKP for statement integrity
                        statement_hash = hashlib.sha3_512(statement_bytes).hexdigest()
                        zkp = generate_zkp(statement_hash)
                        if not verify_zkp(statement_hash, zkp):
                            logger.warning(f"ZKP verification failed for statement_hash={statement_hash[:16]}...")
                            raise RuntimeError("Statement integrity verification failed")
                        statement["zkp"] = zkp

                        # Log to QLDB
                        qldb_event_data = {
                            "statement_hash": statement_hash,
                            "verifier_pubkey": verifier_pubkey[:16],
                            "signature": signature
                        }
                        self.logger.log_event("lighthouse_witness_statement", qldb_event_data)

                        # Log to public feed (anonymized)
                        public_event_data = {
                            "type": "witness_statement_submitted",
                            "time": int(time.time()),
                            "statement_hash": statement_hash,
                            "signature": signature,
                            "public_key": pub_key
                        }
                        self.public_feed.publish_event("witness_statement_submitted", public_event_data)

                        # Publish to AWS IoT
                        payload = {
                            "statement_hash": statement_hash,
                            "verifier_pubkey": verifier_pubkey[:16],
                            "public_key": pub_key[:16]
                        }
                        payload_bytes = cbor2.dumps(payload)
                        signature = self.signer.sign(payload_bytes, priv_key)
                        signed_payload = {'data': payload, 'signature': signature}

                        try:
                            self.iot_client.publish(
                                topic=f"{IOT_TOPIC_PREFIX}/lighthouse/statement",
                                qos=1,
                                payload=cbor2.dumps(signed_payload)
                            )
                        except ClientError as e:
                            logger.warning(f"IoT publish error: {e}")

                        # Cache statement for 300 seconds
                        self.redis_client.setex(cache_key, 300, json.dumps(statement))

                        logger.info(f"Submitted witness statement: statement_hash={statement_hash[:16]}...")
                        return statement
                    except ClientError as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for submit_witness_statement: {e}")
                            time.sleep(2 ** attempt)
                        else:
                            logger.error(f"Failed to submit statement after {retries} attempts: {e}")
                            raise
            except Exception as e:
                logger.error(f"Lighthouse witness statement submission failed: {e}")
                raise

# Example usage
if __name__ == "__main__":
    lighthouse = Lighthouse()
    report = {"abuse": "Documented arbitrary detention", "location": "Region Z", "timestamp": time.time()}
    result = lighthouse.submit_lighthouse_report(report, "user_demo_key", ["ngo_key_1", "ngo_key_2"])
    print(result)
    processed = lighthouse.process_local_reports()
    print(f"Processed reports: {processed}")
    statement_data = {"incident": "Human rights violation", "evidence": "video"}
    statement = lighthouse.submit_witness_statement(statement_data, "verifier_key")
    print(statement)