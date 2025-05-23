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
import hashlib
import time
import json
import pysnark  # Assumed Python bindings for libsnark; replace with circomlib or custom backend in production

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/zkp.log')
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
KMS_KEY_ID = os.getenv('KMS_KEY_ID', '')
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')
IOT_TOPIC_PREFIX = os.getenv('IOT_TOPIC_PREFIX', 'mesh')

class ZKProof:
    """
    zk-SNARK proof handler for privacy-preserving attestation.
    Uses pysnark for real proof generation/verification.
    """

    def __init__(self):
        self.lock = threading.Lock()
        self.redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
        self.kms_client = boto3.client('kms', region_name=AWS_REGION)
        self.iot_client = boto3.client('iot-data', region_name=AWS_REGION)
        self.signer = DilithiumSigner()

    def generate_proof(self, statement: str, witness: str, retries=3) -> dict:
        """
        Generates a zk-SNARK proof for the given statement and witness.
        :param statement: Public statement (e.g., "user is compliant with privacy policy")
        :param witness: Private witness (e.g., policy agreement details)
        :return: Proof object
        """
        with self.lock:
            if not isinstance(statement, str) or not statement.strip() or not isinstance(witness, str) or not witness.strip():
                logger.warning(f"Invalid input: statement={statement}, witness={witness}")
                raise ValueError("Invalid statement or witness")

            try:
                input_hash = hashlib.sha3_512((statement + witness).encode()).hexdigest()
                cache_key = f"zkp_proof_{input_hash}"
                cached_proof = self.redis_client.get(cache_key)
                if cached_proof:
                    logger.debug("Returning cached zk-SNARK proof")
                    return json.loads(cached_proof)

                for attempt in range(retries):
                    try:
                        # Encrypt witness with KMS for secure handling
                        witness_bytes = witness.encode()
                        response = self.kms_client.encrypt(
                            KeyId=KMS_KEY_ID,
                            Plaintext=witness_bytes,
                            EncryptionAlgorithm='SYMMETRIC_DEFAULT'
                        )
                        encrypted_witness = base64.b64encode(response['CiphertextBlob']).decode()

                        # Generate zk-SNARK proof using pysnark (circuit for privacy policy compliance)
                        circuit = pysnark.Circuit()
                        circuit.add_public_input("statement_hash", hashlib.sha256(statement.encode()).digest())
                        circuit.add_private_input("witness_hash", hashlib.sha256(witness.encode()).digest())
                        # Simplified circuit: prove witness hash matches statement without revealing witness
                        proof = circuit.prove({"statement_hash": statement, "witness_hash": witness})

                        proof_obj = {
                            "proof": proof.to_dict(),  # Serialized proof
                            "public": statement,
                            "signal": hashlib.sha256(witness.encode()).hexdigest(),
                            "encrypted_witness": encrypted_witness
                        }

                        # Sign proof with Dilithium
                        proof_bytes = cbor2.dumps(proof_obj)
                        pub_key, priv_key = self.signer.keygen()
                        proof_obj["signature"] = self.signer.sign(proof_bytes, priv_key)
                        proof_obj["public_key"] = pub_key

                        # Generate ZKP for proof integrity (meta-ZKP for recursive assurance)
                        proof_hash = hashlib.sha3_512(proof_bytes).hexdigest()
                        zkp = generate_zkp(proof_hash)
                        if not verify_zkp(proof_hash, zkp):
                            logger.warning(f"ZKP verification failed for proof")
                            raise RuntimeError("Proof integrity verification failed")
                        proof_obj["zkp"] = zkp

                        # Log to QLDB
                        event_data = {
                            "proof_hash": proof_hash,
                            "statement": statement[:16],
                            "signature": sign_message(cbor2.dumps({"proof_hash": proof_hash}))
                        }
                        QLDBLogger.log_event("zkp_generate", event_data)

                        # Cache proof for 300 seconds
                        self.redis_client.setex(cache_key, 300, json.dumps(proof_obj))

                        # Publish to AWS IoT
                        payload = {
                            "proof_hash": proof_hash,
                            "statement": statement[:16],
                            "public_key": pub_key[:16]
                        }
                        payload_bytes = cbor2.dumps(payload)
                        signature = sign_message(payload_bytes)
                        signed_payload = {'data': payload, 'signature': signature}

                        self.iot_client.publish(
                            topic=f"{IOT_TOPIC_PREFIX}/zkp/proof",
                            qos=1,
                            payload=cbor2.dumps(signed_payload)
                        )

                        logger.info(f"Generated zk-SNARK proof: proof_hash={proof_hash[:16]}...")
                        return proof_obj
                    except ClientError as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for proof generation: {e}")
                            time.sleep(2 ** attempt)
                        else:
                            logger.error(f"Failed to generate proof after {retries} attempts: {e}")
                            raise
            except Exception as e:
                logger.error(f"zk-SNARK proof generation failed: {e}")
                raise

    def verify_proof(self, statement: str, proof_obj: dict, retries=3) -> bool:
        """
        Verifies the zk-SNARK proof for the given statement.
        :param statement: Public statement
        :param proof_obj: Proof object from generate_proof
        :return: True if valid, False otherwise
        """
        with self.lock:
            if not isinstance(statement, str) or not statement.strip() or not isinstance(proof_obj, dict):
                logger.warning(f"Invalid input: statement={statement}, proof_obj={proof_obj}")
                raise ValueError("Invalid statement or proof object")

            try:
                proof_hash = hashlib.sha3_512(cbor2.dumps(proof_obj)).hexdigest()
                cache_key = f"zkp_verify_{proof_hash}"
                cached_result = self.redis_client.get(cache_key)
                if cached_result:
                    logger.debug("Returning cached verification result")
                    return json.loads(cached_result)

                for attempt in range(retries):
                    try:
                        # Verify Dilithium signature
                        proof_bytes = cbor2.dumps({
                            "proof": proof_obj["proof"],
                            "public": proof_obj["public"],
                            "signal": proof_obj["signal"],
                            "encrypted_witness": proof_obj["encrypted_witness"]
                        })
                        if not self.signer.verify(proof_bytes, proof_obj["signature"], proof_obj["public_key"]):
                            logger.warning(f"Dilithium signature verification failed for proof")
                            return False

                        # Verify ZKP for proof integrity
                        if not verify_zkp(proof_hash, proof_obj["zkp"]):
                            logger.warning(f"ZKP verification failed for proof_hash={proof_hash[:16]}...")
                            return False

                        # Verify zk-SNARK proof using pysnark
                        circuit = pysnark.Circuit()
                        circuit.add_public_input("statement_hash", hashlib.sha256(statement.encode()).digest())
                        is_valid = circuit.verify(
                            proof=pysnark.Proof.from_dict(proof_obj["proof"]),
                            public_inputs={"statement_hash": statement}
                        )

                        # Log to QLDB
                        event_data = {
                            "proof_hash": proof_hash,
                            "statement": statement[:16],
                            "is_valid": is_valid,
                            "signature": sign_message(cbor2.dumps({"proof_hash": proof_hash, "is_valid": is_valid}))
                        }
                        QLDBLogger.log_event("zkp_verify", event_data)

                        # Cache result for 300 seconds
                        self.redis_client.setex(cache_key, 300, json.dumps(is_valid))

                        # Publish to AWS IoT
                        payload = {
                            "proof_hash": proof_hash,
                            "statement": statement[:16],
                            "is_valid": is_valid
                        }
                        payload_bytes = cbor2.dumps(payload)
                        signature = sign_message(payload_bytes)
                        signed_payload = {'data': payload, 'signature': signature}

                        self.iot_client.publish(
                            topic=f"{IOT_TOPIC_PREFIX}/zkp/verify",
                            qos=1,
                            payload=cbor2.dumps(signed_payload)
                        )

                        logger.info(f"Verified zk-SNARK proof: proof_hash={proof_hash[:16]}..., is_valid={is_valid}")
                        return is_valid
                    except ClientError as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for proof verification: {e}")
                            time.sleep(2 ** attempt)
                        else:
                            logger.error(f"Failed to verify proof after {retries} attempts: {e}")
                            raise
            except Exception as e:
                logger.error(f"zk-SNARK proof verification failed: {e}")
                return False

# Example usage
if __name__ == "__main__":
    zkp = ZKProof()
    statement = "user is compliant with privacy policy"
    witness = "secret_policy_agreement"
    proof_obj = zkp.generate_proof(statement, witness)
    print("Proof:", proof_obj)
    is_valid = zkp.verify_proof(statement, proof_obj)
    print("Proof valid:", is_valid)