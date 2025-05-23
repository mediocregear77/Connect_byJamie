import time
import threading
import logging
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
from human_rights.ngo_api.witness_verifier import WitnessVerifier
import hashlib
import orjson
from jsonschema import validate, ValidationError
import requests

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/human_rights_monitor.log')
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')
IOT_TOPIC_PREFIX = os.getenv('IOT_TOPIC_PREFIX', 'mesh')
ATTESTATION_INTERVAL = int(os.getenv('ATTESTATION_INTERVAL', 3600))  # 1 hour
NGO_API_ENDPOINTS = json.loads(os.getenv('NGO_API_ENDPOINTS', '{}'))  # Dict of NGO_name -> API endpoint

# JSON schema for incidents
INCIDENT_SCHEMA = {
    "type": "object",
    "properties": {
        "statement_id": {"type": "string"},
        "report": {"type": "object"},
        "verified_by": {"type": "string"},
        "verified_at": {"type": "number"}
    },
    "required": ["statement_id", "report", "verified_by", "verified_at"]
}

# JSON schema for attestations
ATTESTATION_SCHEMA = {
    "type": "object",
    "properties": {
        "attestation": {"type": "string"},
        "signature": {"type": "string"},
        "monitor_id": {"type": "string"},
        "timestamp": {"type": "number"},
        "public_key": {"type": "string"},
        "zkp": {"type": "object"}
    },
    "required": ["attestation", "signature", "monitor_id", "timestamp"]
}

class HumanRightsMonitor:
    """
    Human Rights Monitor Node for processing, verifying, and attesting witness statements.
    Integrates with Dilithium signatures, zk-SNARKs, and AWS services for secure operations.
    """

    def __init__(self, node_id, keypair, node_registry, ngo_pubkeys):
        """
        :param node_id: Unique node identifier for this monitor
        :param keypair: Tuple (privkey, pubkey) for Dilithium signing
        :param node_registry: Function or object for resolving node_id to public key
        :param ngo_pubkeys: Dict of NGO_name -> public key for outgoing attestations
        """
        self.node_id = node_id
        self.privkey, self.pubkey = keypair
        self.witness_verifier = WitnessVerifier(node_registry)
        self.ngo_pubkeys = ngo_pubkeys
        self.ledger = []
        self.incident_channel = []
        self.lock = threading.Lock()
        self.redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
        self.iot_client = boto3.client('iot-data', region_name=AWS_REGION)
        self.logger = QLDBLogger()
        self.public_feed = PublicFeed()
        self.zkp = ZKProof()
        self.signer = DilithiumSigner()

    def receive_statement(self, statement, retries=3):
        """
        Receives and verifies witness statements. Appends valid incidents to local ledger and logs to QLDB.
        """
        with self.lock:
            try:
                statement_id = statement.get("statement_id", "unknown")
                statement_hash = hashlib.sha3_512(orjson.dumps(statement, option=orjson.OPT_SORT_KEYS)).hexdigest()
                cache_key = f"monitor_statement_{statement_hash}"
                cached_result = self.redis_client.get(cache_key)
                if cached_result:
                    logger.debug(f"Returning cached statement processing: statement_id={statement_id}")
                    return json.loads(cached_result)

                for attempt in range(retries):
                    try:
                        valid, msg = self.witness_verifier.verify_statement(statement)
                        if valid:
                            incident = {
                                "statement_id": statement_id,
                                "report": statement["report"],
                                "verified_by": self.node_id,
                                "verified_at": int(time.time()),
                            }
                            validate(instance=incident, schema=INCIDENT_SCHEMA)

                            self.ledger.append(incident)
                            self.incident_channel.append(incident)

                            # Log to QLDB
                            qldb_event_data = {
                                "statement_id": statement_id,
                                "statement_hash": statement_hash,
                                "verified_by": self.node_id,
                                "signature": self.signer.sign(
                                    cbor2.dumps({"statement_id": statement_id}),
                                    self.privkey
                                )
                            }
                            self.logger.log_event("VerifiedIncident", qldb_event_data)

                            # Log to public feed (anonymized)
                            public_event_data = {
                                "type": "incident_verified",
                                "time": incident["verified_at"],
                                "statement_id": statement_id,
                                "statement_hash": statement_hash
                            }
                            self.public_feed.publish_event("incident_verified", public_event_data)

                            # Publish to AWS IoT
                            payload = {
                                "statement_id": statement_id,
                                "statement_hash": statement_hash[:16],
                                "verified_by": self.node_id
                            }
                            payload_bytes = cbor2.dumps(payload)
                            signature = self.signer.sign(payload_bytes, self.privkey)
                            signed_payload = {'data': payload, 'signature': signature}

                            try:
                                self.iot_client.publish(
                                    topic=f"{IOT_TOPIC_PREFIX}/monitor/incident",
                                    qos=1,
                                    payload=cbor2.dumps(signed_payload)
                                )
                            except ClientError as e:
                                logger.warning(f"IoT publish error: {e}")

                            # Cache result for 300 seconds
                            result = {"status": "verified", "incident": incident}
                            self.redis_client.setex(cache_key, 300, json.dumps(result))

                            logger.info(f"Incident verified and logged: statement_id={statement_id}, statement_hash={statement_hash[:16]}...")
                            return result
                        else:
                            logger.warning(f"Statement rejected: statement_id={statement_id}, reason={msg}")
                            return {"status": "rejected", "message": msg}
                    except Exception as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for receive_statement: {e}")
                            time.sleep(2 ** attempt)
                        else:
                            logger.error(f"Failed to process statement after {retries} attempts: {e}")
                            raise
            except ValidationError as e:
                logger.error(f"Invalid incident schema for statement_id={statement_id}: {e}")
                raise
            except Exception as e:
                logger.error(f"Statement processing failed for statement_id={statement_id}: {e}")
                raise

    def sign_attestation(self, incident, retries=3):
        """
        Creates a signed attestation for a verified incident, for NGO delivery.
        """
        with self.lock:
            try:
                statement_id = incident["statement_id"]
                incident_hash = hashlib.sha3_512(orjson.dumps(incident, option=orjson.OPT_SORT_KEYS)).hexdigest()
                cache_key = f"monitor_attestation_{incident_hash}"
                cached_attestation = self.redis_client.get(cache_key)
                if cached_attestation:
                    logger.debug(f"Returning cached attestation: statement_id={statement_id}")
                    return json.loads(cached_attestation)

                for attempt in range(retries):
                    try:
                        message = f"{incident['statement_id']}|{orjson.dumps(incident['report'], option=orjson.OPT_SORT_KEYS).decode()}|{incident['verified_at']}".encode()
                        signature = self.signer.sign(message, self.privkey)

                        attestation = {
                            "attestation": message.hex(),
                            "signature": signature,
                            "monitor_id": self.node_id,
                            "timestamp": int(time.time()),
                            "public_key": self.pubkey
                        }

                        # Generate ZKP for attestation integrity
                        attestation_bytes = cbor2.dumps(attestation)
                        attestation_hash = hashlib.sha3_512(attestation_bytes).hexdigest()
                        zkp = self.zkp.generate_proof(attestation_hash, f"secret:{attestation_hash}")
                        if not self.zkp.verify_proof(attestation_hash, zkp):
                            logger.warning(f"ZKP verification failed for attestation_hash={attestation_hash[:16]}...")
                            raise RuntimeError("Attestation integrity verification failed")
                        attestation["zkp"] = zkp

                        validate(instance=attestation, schema=ATTESTATION_SCHEMA)

                        # Log to QLDB
                        qldb_event_data = {
                            "attestation_hash": attestation_hash,
                            "statement_id": statement_id,
                            "monitor_id": self.node_id,
                            "signature": signature
                        }
                        self.logger.log_event("NGOAttestation", qldb_event_data)

                        # Cache attestation for 300 seconds
                        self.redis_client.setex(cache_key, 300, json.dumps(attestation))

                        # Publish to AWS IoT
                        payload = {
                            "attestation_hash": attestation_hash[:16],
                            "statement_id": statement_id,
                            "monitor_id": self.node_id
                        }
                        payload_bytes = cbor2.dumps(payload)
                        signature = self.signer.sign(payload_bytes, self.privkey)
                        signed_payload = {'data': payload, 'signature': signature}

                        try:
                            self.iot_client.publish(
                                topic=f"{IOT_TOPIC_PREFIX}/monitor/attestation",
                                qos=1,
                                payload=cbor2.dumps(signed_payload)
                            )
                        except ClientError as e:
                            logger.warning(f"IoT publish error: {e}")

                        logger.info(f"Signed attestation: statement_id={statement_id}, attestation_hash={attestation_hash[:16]}...")
                        return attestation
                    except Exception as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for sign_attestation: {e}")
                            time.sleep(2 ** attempt)
                        else:
                            logger.error(f"Failed to sign attestation after {retries} attempts: {e}")
                            raise
            except ValidationError as e:
                logger.error(f"Invalid attestation schema for statement_id={incident.get('statement_id', 'unknown')}: {e}")
                raise
            except Exception as e:
                logger.error(f"Attestation signing failed for statement_id={incident.get('statement_id', 'unknown')}: {e}")
                raise

    def batch_sign_attestations(self, incidents, retries=3):
        """
        Creates signed attestations for multiple verified incidents in a batch.
        """
        with self.lock:
            if not isinstance(incidents, list) or not all(isinstance(i, dict) for i in incidents):
                logger.warning(f"Invalid incidents: {incidents}")
                raise ValueError("Incidents must be a list of dictionaries")

            try:
                incidents_hash = hashlib.sha3_512(orjson.dumps(incidents, option=orjson.OPT_SORT_KEYS)).hexdigest()
                cache_key = f"monitor_batch_attestations_{incidents_hash}"
                cached_attestations = self.redis_client.get(cache_key)
                if cached_attestations:
                    logger.debug(f"Returning cached batch attestations: incidents_hash={incidents_hash[:16]}...")
                    return json.loads(cached_attestations)

                attestations = []
                for attempt in range(retries):
                    try:
                        for incident in incidents:
                            attestation = self.sign_attestation(incident)
                            attestations.append(attestation)

                        # Log to QLDB
                        batch_hash = hashlib.sha3_512(orjson.dumps(attestations, option=orjson.OPT_SORT_KEYS)).hexdigest()
                        qldb_event_data = {
                            "batch_hash": batch_hash,
                            "attestation_count": len(attestations),
                            "signature": self.signer.sign(
                                cbor2.dumps({"batch_hash": batch_hash}),
                                self.privkey
                            )
                        }
                        self.logger.log_event("NGOAttestationBatch", qldb_event_data)

                        # Cache attestations for 300 seconds
                        self.redis_client.setex(cache_key, 300, json.dumps(attestations))

                        # Publish to AWS IoT
                        payload = {
                            "batch_hash": batch_hash[:16],
                            "attestation_count": len(attestations)
                        }
                        payload_bytes = cbor2.dumps(payload)
                        signature = self.signer.sign(payload_bytes, self.privkey)
                        signed_payload = {'data': payload, 'signature': signature}

                        try:
                            self.iot_client.publish(
                                topic=f"{IOT_TOPIC_PREFIX}/monitor/batch_attestation",
                                qos=1,
                                payload=cbor2.dumps(signed_payload)
                            )
                        except ClientError as e:
                            logger.warning(f"IoT publish error: {e}")

                        logger.info(f"Signed {len(attestations)} attestations in batch: batch_hash={batch_hash[:16]}...")
                        return attestations
                    except Exception as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for batch_sign_attestations: {e}")
                            time.sleep(2 ** attempt)
                        else:
                            logger.error(f"Failed to sign batch attestations after {retries} attempts: {e}")
                            raise
            except Exception as e:
                logger.error(f"Batch attestation signing failed: {e}")
                raise

    def periodic_attestation_report(self):
        """
        Periodically bundles new incidents, signs attestations, and sends to NGOs.
        """
        while True:
            try:
                with self.lock:
                    batch = list(self.incident_channel)
                    self.incident_channel.clear()

                if batch:
                    attestations = self.batch_sign_attestations(batch)
                    batch_hash = hashlib.sha3_512(orjson.dumps(attestations, option=orjson.OPT_SORT_KEYS)).hexdigest()

                    # Deliver to NGOs via API
                    for ngo_name, endpoint in NGO_API_ENDPOINTS.items():
                        try:
                            response = requests.post(
                                f"{endpoint}/api/lighthouse/batch_report",
                                json=attestations,
                                timeout=10
                            )
                            if response.status_code == 200:
                                logger.info(f"Delivered {len(attestations)} attestations to NGO {ngo_name}: batch_hash={batch_hash[:16]}...")
                            else:
                                logger.warning(f"Failed to deliver to NGO {ngo_name}: status={response.status_code}")
                        except requests.RequestException as e:
                            logger.error(f"Failed to deliver to NGO {ngo_name}: {e}")

                    # Log to QLDB
                    qldb_event_data = {
                        "batch_hash": batch_hash,
                        "attestation_count": len(attestations),
                        "ngo_count": len(NGO_API_ENDPOINTS),
                        "signature": self.signer.sign(
                            cbor2.dumps({"batch_hash": batch_hash}),
                            self.privkey
                        )
                    }
                    self.logger.log_event("NGOAttestationDelivery", qldb_event_data)

                    # Log to public feed (anonymized)
                    public_event_data = {
                        "type": "ngo_attestation_delivered",
                        "time": int(time.time()),
                        "batch_hash": batch_hash,
                        "attestation_count": len(attestations)
                    }
                    self.public_feed.publish_event("ngo_attestation_delivered", public_event_data)

                time.sleep(ATTESTATION_INTERVAL)
            except Exception as e:
                logger.error(f"Periodic attestation report failed: {e}")
                time.sleep(60)  # Retry after 1 minute on error

# Example usage
if __name__ == "__main__":
    node_id = "monitor001"
    privkey, pubkey = "DEMO_PRIVKEY", "DEMO_PUBKEY"
    node_registry = lambda node_id: "SENDER_PUBKEY"
    ngo_pubkeys = {"NGO_1": "PUBKEY_NGO_1"}
    monitor = HumanRightsMonitor(node_id, (privkey, pubkey), node_registry, ngo_pubkeys)

    threading.Thread(target=monitor.periodic_attestation_report, daemon=True).start()

    example_statement = {
        "statement_id": "stmt456",
        "report": {"event": "Abuse Reported", "details": "Incident details here."},
        "signature": "deadbeef" * 16,
        "sender_node": "node42",
        "timestamp": int(time.time()),
        "public_key": "SENDER_PUBKEY"
    }
    result = monitor.receive_statement(example_statement)
    print(f"Statement Processing Result: {result}")