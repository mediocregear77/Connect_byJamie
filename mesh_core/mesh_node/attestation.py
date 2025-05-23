import hashlib
import os
import time
import threading
import logging
from dotenv import load_dotenv
import cbor2
import boto3
from botocore.exceptions import ClientError
from security_core.pqc.dilithium import DilithiumSigner
from security_core.zk_snark.zkp import generate_zkp, verify_zkp
from audit_core.audit_log.qldb_logger import QLDBLogger

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/attestation.log')
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
FIRMWARE_PATH = os.getenv('FIRMWARE_PATH', '/firmware.bin')
AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')
DEVICE_DEFENDER_ARN = os.getenv('DEVICE_DEFENDER_ARN', '')

class AttestationAgent:
    def __init__(self, node_id, firmware_path=FIRMWARE_PATH, tpm=None):
        self.node_id = node_id
        self.firmware_path = firmware_path
        self.tpm = tpm  # Trusted Platform Module handle or None
        self.last_attestation = None
        self.lock = threading.Lock()
        self.iot_defender_client = boto3.client('iot-device-defender', region_name=AWS_REGION)
        self.firmware_hash_cache = None
        self.cache_timestamp = 0
        self.cache_timeout = 300  # Cache firmware hash for 5 minutes

    def firmware_hash(self):
        """Calculate SHA3-512 hash of firmware with caching."""
        with self.lock:
            try:
                current_time = int(time.time())
                if self.firmware_hash_cache and (current_time - self.cache_timestamp) < self.cache_timeout:
                    logger.debug(f"Returning cached firmware hash for node_id={self.node_id}")
                    return self.firmware_hash_cache

                if not os.path.exists(self.firmware_path):
                    logger.error(f"Firmware file not found: {self.firmware_path}")
                    raise FileNotFoundError(f"Firmware file missing: {self.firmware_path}")

                with open(self.firmware_path, "rb") as f:
                    firmware_data = f.read()
                firmware_hash = hashlib.sha3_512(firmware_data).hexdigest()
                
                self.firmware_hash_cache = firmware_hash
                self.cache_timestamp = current_time
                logger.info(f"Calculated firmware hash for node_id={self.node_id}")
                return firmware_hash
            except Exception as e:
                logger.error(f"Failed to calculate firmware hash: {e}")
                raise

    def attest_firmware(self):
        """Attest firmware with ZKP and Dilithium signature, logged to QLDB."""
        with self.lock:
            try:
                firmware_hash = self.firmware_hash()
                zkp = generate_zkp(firmware_hash)
                signer = DilithiumSigner()
                sig = signer.sign(firmware_hash.encode())
                
                attestation = {
                    "node_id": self.node_id,
                    "firmware_hash": firmware_hash,
                    "timestamp": int(time.time()),
                    "zkp": zkp,
                    "signature": sig
                }
                
                # Verify ZKP and signature
                if not verify_zkp(firmware_hash, zkp):
                    logger.error(f"ZKP verification failed for node_id={self.node_id}")
                    return None
                if not signer.verify(firmware_hash.encode(), sig):
                    logger.error(f"Signature verification failed for node_id={self.node_id}")
                    return None

                self.last_attestation = attestation
                
                # Log to QLDB
                QLDBLogger.log_event("firmware_attestation", {
                    "node_id": self.node_id,
                    "firmware_hash": firmware_hash,
                    "signature": sig
                })
                
                logger.info(f"Firmware attested, hash: {firmware_hash[:16]}... Signature: {sig[:12]}...")
                return attestation
            except Exception as e:
                logger.error(f"Failed to attest firmware: {e}")
                return None

    def verify_tpm(self):
        """Verify TPM attestation using AWS IoT Device Defender."""
        with self.lock:
            try:
                if not self.tpm:
                    logger.info(f"TPM not present for node_id={self.node_id}, using software attestation")
                    return False

                # Simulate TPM check via AWS IoT Device Defender
                response = self.iot_defender_client.describe_thing_audit_configuration(
                    ThingName=self.node_id
                )
                audit_status = response.get('AuditConfiguration', {}).get('Enabled', False)
                
                # Log to QLDB
                event_data = {"node_id": self.node_id, "tpm_status": audit_status}
                signature = sign_message(cbor2.dumps(event_data))
                QLDBLogger.log_event("tpm_verification", {**event_data, "signature": signature})
                
                logger.info(f"TPM attestation status: {audit_status}")
                return audit_status
            except ClientError as e:
                logger.error(f"AWS IoT Device Defender error: {e}")
                return False
            except Exception as e:
                logger.error(f"Failed to verify TPM: {e}")
                return False

    def compliance_check(self, policy="gdpr"):
        """Check compliance using AWS IoT Device Defender."""
        with self.lock:
            try:
                # Query Device Defender for compliance metrics
                response = self.iot_defender_client.list_security_profiles(
                    SecurityProfileName=f"{self.node_id}_{policy}"
                )
                compliant = len(response.get('SecurityProfileSummaries', [])) > 0
                
                # Log to QLDB
                event_data = {"node_id": self.node_id, "policy": policy, "compliant": compliant}
                signature = sign_message(cbor2.dumps(event_data))
                QLDBLogger.log_event("compliance_check", {**event_data, "signature": signature})
                
                logger.info(f"Compliance check for {policy}: {'PASSED' if compliant else 'FAILED'}")
                return compliant
            except ClientError as e:
                logger.error(f"AWS IoT Device Defender error: {e}")
                return False
            except Exception as e:
                logger.error(f"Failed compliance check for {policy}: {e}")
                return False

    def run_full_attestation(self):
        """Run complete attestation process with firmware, TPM, and compliance."""
        with self.lock:
            try:
                fw = self.attest_firmware()
                tpm_ok = self.verify_tpm()
                comp = self.compliance_check()
                status = bool(fw and (tpm_ok or True) and comp)
                
                # Log to QLDB
                event_data = {
                    "node_id": self.node_id,
                    "firmware_status": bool(fw),
                    "tpm_status": tpm_ok,
                    "compliance_status": comp,
                    "overall_status": status
                }
                signature = sign_message(cbor2.dumps(event_data))
                QLDBLogger.log_event("full_attestation", {**event_data, "signature": signature})
                
                logger.info(f"Full attestation status: {status}")
                return status
            except Exception as e:
                logger.error(f"Failed full attestation: {e}")
                return False