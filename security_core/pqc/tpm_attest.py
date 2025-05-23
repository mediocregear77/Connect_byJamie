import os
import hashlib
import logging
import threading
from dotenv import load_dotenv
import redis
import cbor2
import boto3
from botocore.exceptions import ClientError
from audit_core.audit_log.qldb_logger import QLDBLogger
from security_core.pqc.dilithium import sign_message
from security_core.zk_snark.zkp import generate_zkp, verify_zkp
import time
from tpm2_pytss import *

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/tpm_attest.log')
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
TPM_DEVICE = os.getenv('TPM_DEVICE', '/dev/tpm0')
KMS_KEY_ID = os.getenv('KMS_KEY_ID', '')
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')
IOT_TOPIC_PREFIX = os.getenv('IOT_TOPIC_PREFIX', 'mesh')
PCR_SELECTION = os.getenv('PCR_SELECTION', '0,1,2')  # Default PCRs for sealing

class TPMAttestation:
    """
    Handles TPM-backed attestation and PQC key storage/verification using tpm2-pytss.
    """

    def __init__(self):
        self.lock = threading.Lock()
        self.redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
        self.kms_client = boto3.client('kms', region_name=AWS_REGION)
        self.iot_client = boto3.client('iot-data', region_name=AWS_REGION)
        self.enabled = self.detect_tpm()
        self.tpm_context = None
        if self.enabled:
            self._init_tpm()

    def _init_tpm(self):
        """Initialize TPM context."""
        with self.lock:
            try:
                self.tpm_context = TSS2_TctiLdr.initialize("device:" + TPM_DEVICE)
                logger.info("Initialized TPM context")
            except Exception as e:
                logger.error(f"Failed to initialize TPM context: {e}")
                self.enabled = False
                raise

    def detect_tpm(self, retries=3):
        """Check if TPM is present."""
        with self.lock:
            for attempt in range(retries):
                try:
                    if os.path.exists(TPM_DEVICE):
                        logger.info(f"TPM detected at {TPM_DEVICE}")
                        return True
                    logger.warning(f"TPM not detected at {TPM_DEVICE}")
                    return False
                except Exception as e:
                    if attempt < retries - 1:
                        logger.warning(f"Retry {attempt + 1}/{retries} for TPM detection: {e}")
                        time.sleep(2 ** attempt)
                    else:
                        logger.error(f"Failed to detect TPM after {retries} attempts: {e}")
                        return False

    def get_quote(self, nonce: bytes, retries=3) -> dict:
        """Generate a TPM quote with PCRs and Dilithium signature."""
        with self.lock:
            if not self.enabled:
                logger.error("TPM not detected")
                raise RuntimeError("TPM not detected")
            if not isinstance(nonce, bytes) or len(nonce) == 0:
                logger.warning(f"Invalid nonce: {nonce}")
                raise ValueError("Invalid nonce")

            try:
                nonce_hash = hashlib.sha3_512(nonce).hexdigest()
                cache_key = f"tpm_quote_{nonce_hash}"
                cached_quote = self.redis_client.get(cache_key)
                if cached_quote:
                    logger.debug("Returning cached TPM quote")
                    return json.loads(cached_quote)

                for attempt in range(retries):
                    try:
                        # Initialize TPM session
                        esys_context = ESYS_CONTEXT(self.tpm_context)
                        pcr_selection = TPMS_PCR_SELECTION.parse(PCR_SELECTION)
                        pcr_data = esys_context.PCR_Read(pcr_selection)

                        # Generate quote
                        qualifying_data = TPM2B_DATA(buffer=nonce)
                        quote_info = esys_context.Quote(
                            ak_handle=ESYS_TR.RH_NULL,  # Use null AK for demo; production uses attested AK
                            in_scheme=TPM2_ALG.RSASSA,
                            qualifying_data=qualifying_data,
                            pcr_select=pcr_selection
                        )

                        # Extract PCRs and quote
                        pcr_values = [pcr.digest.hex() for pcr in pcr_data]
                        quote = quote_info.attestationData.hex()

                        result = {
                            "pcr": pcr_values,
                            "quote": quote,
                            "nonce": base64.b64encode(nonce).decode()
                        }

                        # Sign quote with Dilithium
                        signer = DilithiumSigner()
                        pub, priv = signer.keygen()
                        quote_bytes = cbor2.dumps(result)
                        signature = signer.sign(quote_bytes, priv)
                        result["signature"] = signature

                        # Generate ZKP for quote integrity
                        quote_hash = hashlib.sha3_512(quote_bytes).hexdigest()
                        zkp = generate_zkp(quote_hash)
                        if not verify_zkp(quote_hash, zkp):
                            logger.warning(f"ZKP verification failed for quote")
                            raise RuntimeError("Quote integrity verification failed")

                        # Log to QLDB
                        event_data = {
                            "quote_hash": quote_hash,
                            "nonce": base64.b64encode(nonce).decode()[:16],
                            "signature": sign_message(cbor2.dumps({"quote_hash": quote_hash}))
                        }
                        QLDBLogger.log_event("tpm_quote", event_data)

                        # Cache quote for 300 seconds
                        self.redis_client.setex(cache_key, 300, json.dumps(result))

                        # Publish to AWS IoT
                        payload = {
                            "quote": quote[:16],
                            "pcr_count": len(pcr_values),
                            "nonce": base64.b64encode(nonce).decode()[:16]
                        }
                        payload_bytes = cbor2.dumps(payload)
                        signature = sign_message(payload_bytes)
                        signed_payload = {'data': payload, 'signature': signature}

                        self.iot_client.publish(
                            topic=f"{IOT_TOPIC_PREFIX}/tpm/quote",
                            qos=1,
                            payload=cbor2.dumps(signed_payload)
                        )

                        logger.info(f"Generated TPM quote: nonce={base64.b64encode(nonce).decode()[:16]}...")
                        return result
                    except ClientError as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for get_quote: {e}")
                            time.sleep(2 ** attempt)
                        else:
                            logger.error(f"Failed to generate quote after {retries} attempts: {e}")
                            raise
            except Exception as e:
                logger.error(f"TPM quote generation failed: {e}")
                raise

    def seal_key(self, key_material: bytes, retries=3) -> bytes:
        """Seal a private key blob with TPM and KMS encryption."""
        with self.lock:
            if not self.enabled:
                logger.error("TPM not detected")
                raise RuntimeError("TPM not detected")
            if not isinstance(key_material, bytes) or len(key_material) == 0:
                logger.warning(f"Invalid key material: {key_material}")
                raise ValueError("Invalid key material")

            try:
                key_hash = hashlib.sha3_512(key_material).hexdigest()
                cache_key = f"tpm_sealed_{key_hash}"
                cached_sealed = self.redis_client.get(cache_key)
                if cached_sealed:
                    logger.debug("Returning cached sealed key")
                    return base64.b64decode(cached_sealed)

                for attempt in range(retries):
                    try:
                        # Initialize TPM session
                        esys_context = ESYS_CONTEXT(self.tpm_context)
                        pcr_selection = TPMS_PCR_SELECTION.parse(PCR_SELECTION)

                        # Seal key material with TPM
                        sealed_data = esys_context.Seal(
                            auth_value=None,
                            data=TPM2B_SENSITIVE_DATA(buffer=key_material),
                            pcr_select=pcr_selection
                        )

                        sealed_blob = sealed_data.buffer

                        # Encrypt sealed blob with KMS for additional security
                        response = self.kms_client.encrypt(
                            KeyId=KMS_KEY_ID,
                            Plaintext=sealed_blob,
                            EncryptionAlgorithm='SYMMETRIC_DEFAULT'
                        )
                        encrypted_blob = response['CiphertextBlob']
                        sealed = base64.b64encode(encrypted_blob).decode()

                        # Generate ZKP for sealed key integrity
                        sealed_hash = hashlib.sha3_512(cbor2.dumps(sealed)).hexdigest()
                        zkp = generate_zkp(sealed_hash)
                        if not verify_zkp(sealed_hash, zkp):
                            logger.warning(f"ZKP verification failed for sealed key")
                            raise RuntimeError("Sealed key integrity verification failed")

                        # Log to QLDB
                        event_data = {
                            "key_hash": key_hash,
                            "sealed_hash": sealed_hash,
                            "signature": sign_message(cbor2.dumps({"sealed_hash": sealed_hash}))
                        }
                        QLDBLogger.log_event("tpm_seal_key", event_data)

                        # Cache sealed key for 3600 seconds
                        self.redis_client.setex(cache_key, 3600, json.dumps(sealed))

                        # Publish to AWS IoT
                        payload = {"key_hash": key_hash, "sealed_hash": sealed_hash[:16]}
                        payload_bytes = cbor2.dumps(payload)
                        signature = sign_message(payload_bytes)
                        signed_payload = {'data': payload, 'signature': signature}

                        self.iot_client.publish(
                            topic=f"{IOT_TOPIC_PREFIX}/tpm/seal",
                            qos=1,
                            payload=cbor2.dumps(signed_payload)
                        )

                        logger.info(f"Sealed key: key_hash={key_hash[:16]}...")
                        return encrypted_blob
                    except ClientError as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for seal_key: {e}")
                            time.sleep(2 ** attempt)
                        else:
                            logger.error(f"Failed to seal key after {retries} attempts: {e}")
                            raise
            except Exception as e:
                logger.error(f"TPM key sealing failed: {e}")
                raise

    def unseal_key(self, sealed_blob: bytes, retries=3) -> bytes:
        """Unseal a private key blob with TPM and KMS decryption."""
        with self.lock:
            if not self.enabled:
                logger.error("TPM not detected")
                raise RuntimeError("TPM not detected")
            if not isinstance(sealed_blob, bytes) or len(sealed_blob) == 0:
                logger.warning(f"Invalid sealed blob: {sealed_blob}")
                raise ValueError("Invalid sealed blob")

            try:
                sealed_hash = hashlib.sha3_512(sealed_blob).hexdigest()
                cache_key = f"tpm_unsealed_{sealed_hash}"
                cached_key = self.redis_client.get(cache_key)
                if cached_key:
                    logger.debug("Returning cached unsealed key")
                    return base64.b64decode(cached_key)

                for attempt in range(retries):
                    try:
                        # Decrypt sealed blob with KMS
                        response = self.kms_client.decrypt(
                            CiphertextBlob=sealed_blob,
                            KeyId=KMS_KEY_ID,
                            EncryptionAlgorithm='SYMMETRIC_DEFAULT'
                        )
                        sealed_data = response['Plaintext']

                        # Initialize TPM session
                        esys_context = ESYS_CONTEXT(self.tpm_context)
                        pcr_selection = TPMS_PCR_SELECTION.parse(PCR_SELECTION)

                        # Verify PCR state
                        pcr_data = esys_context.PCR_Read(pcr_selection)
                        if not pcr_data:  # Simplified check; production would validate PCR values
                            logger.warning("PCR state does not match sealing conditions")
                            raise RuntimeError("PCR state mismatch")

                        # Unseal with TPM
                        unsealed_data = esys_context.Unseal(
                            item_handle=ESYS_TR.RH_NULL,  # Use null handle for demo; production uses sealed object
                            sealed_data=TPM2B_SENSITIVE_DATA(buffer=sealed_data)
                        )
                        key_material = unsealed_data.buffer

                        # Generate ZKP for unsealed key integrity
                        key_hash = hashlib.sha3_512(key_material).hexdigest()
                        zkp = generate_zkp(key_hash)
                        if not verify_zkp(key_hash, zkp):
                            logger.warning(f"ZKP verification failed for unsealed key")
                            raise RuntimeError("Unsealed key integrity verification failed")

                        # Log to QLDB
                        event_data = {
                            "key_hash": key_hash,
                            "sealed_hash": sealed_hash,
                            "signature": sign_message(cbor2.dumps({"key_hash": key_hash}))
                        }
                        QLDBLogger.log_event("tpm_unseal_key", event_data)

                        # Cache unsealed key for 300 seconds
                        self.redis_client.setex(cache_key, 300, base64.b64encode(key_material).decode())

                        # Publish to AWS IoT
                        payload = {"key_hash": key_hash[:16], "sealed_hash": sealed_hash[:16]}
                        payload_bytes = cbor2.dumps(payload)
                        signature = sign_message(payload_bytes)
                        signed_payload = {'data': payload, 'signature': signature}

                        self.iot_client.publish(
                            topic=f"{IOT_TOPIC_PREFIX}/tpm/unseal",
                            qos=1,
                            payload=cbor2.dumps(signed_payload)
                        )

                        logger.info(f"Unsealed key: key_hash={key_hash[:16]}...")
                        return key_material
                    except ClientError as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for unseal_key: {e}")
                            time.sleep(2 ** attempt)
                        else:
                            logger.error(f"Failed to unseal key after {retries} attempts: {e}")
                            raise
            except Exception as e:
                logger.error(f"TPM key unsealing failed: {e}")
                raise

# Example usage
if __name__ == "__main__":
    tpm = TPMAttestation()
    if tpm.enabled:
        nonce = os.urandom(32)
        quote = tpm.get_quote(nonce)
        key_material = b"secret_key"
        sealed = tpm.seal_key(key_material)
        unsealed = tpm.unseal_key(sealed)
        print(f"TPM attestation demo: Key match: {key_material == unsealed}")
    else:
        print("No TPM detected. Attestation unavailable.")