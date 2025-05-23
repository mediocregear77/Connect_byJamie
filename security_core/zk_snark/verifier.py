import logging
import threading
from multiprocessing import Pool
from dotenv import load_dotenv
import os
import redis
import cbor2
import boto3
from botocore.exceptions import ClientError
from audit_core.audit_log.qldb_logger import QLDBLogger
from security_core.pqc.dilithium import DilithiumSigner
from .zkp import ZKProof
import hashlib
import time
import json

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/verifier.log')
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')
IOT_TOPIC_PREFIX = os.getenv('IOT_TOPIC_PREFIX', 'mesh')
BATCH_SIZE = int(os.getenv('ZKP_BATCH_SIZE', 10))

class ProofVerifier:
    """
    Verifies zk-SNARK proofs for statements required by mesh attestation.
    Integrates with Dilithium signatures and AWS IoT for secure verification.
    """

    def __init__(self):
        self.lock = threading.Lock()
        self.redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
        self.iot_client = boto3.client('iot-data', region_name=AWS_REGION)
        self.signer = DilithiumSigner()
        self.zk_proof = ZKProof()

    def verify(self, statement: str, proof_obj: dict, trust_score=1.0, retries=3) -> bool:
        """
        Verifies a zk-SNARK proof for a given statement with trust score weighting.
        :param statement: Public statement
        :param proof_obj: Proof object from ZKProof.generate_proof
        :param trust_score: Float (node's trust score, default 1.0)
        :return: True if valid, False otherwise
        """
        with self.lock:
            if not isinstance(statement, str) or not statement.strip() or not isinstance(proof_obj, dict):
                logger.warning(f"Invalid input: statement={statement}, proof_obj={proof_obj}")
                raise ValueError("Invalid statement or proof object")

            try:
                proof_hash = hashlib.sha3_512(cbor2.dumps(proof_obj)).hexdigest()
                cache_key = f"zkp_verify_single_{proof_hash}"
                cached_result = self.redis_client.get(cache_key)
                if cached_result:
                    logger.debug("Returning cached single verification result")
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
                            logger.warning(f"Dilithium signature verification failed for proof_hash={proof_hash[:16]}...")
                            return False

                        # Verify zk-SNARK proof
                        is_valid = self.zk_proof.verify_proof(statement, proof_obj)

                        # Adjust validity based on trust score (e.g., require higher confidence for low-trust nodes)
                        if trust_score < 0.5 and is_valid:
                            is_valid = False  # Conservative: reject proofs from low-trust nodes
                            logger.warning(f"Proof rejected due to low trust_score={trust_score}")

                        # Log to QLDB
                        event_data = {
                            "proof_hash": proof_hash,
                            "statement": statement[:16],
                            "is_valid": is_valid,
                            "trust_score": trust_score,
                            "signature": sign_message(cbor2.dumps({"proof_hash": proof_hash, "is_valid": is_valid}))
                        }
                        QLDBLogger.log_event("zkp_single_verify", event_data)

                        # Cache result for 300 seconds
                        self.redis_client.setex(cache_key, 300, json.dumps(is_valid))

                        # Publish to AWS IoT
                        payload = {
                            "proof_hash": proof_hash,
                            "statement": statement[:16],
                            "is_valid": is_valid,
                            "trust_score": trust_score
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
                            logger.warning(f"Retry {attempt + 1}/{retries} for single verification: {e}")
                            time.sleep(2 ** attempt)
                        else:
                            logger.error(f"Failed to verify proof after {retries} attempts: {e}")
                            raise
            except Exception as e:
                logger.error(f"zk-SNARK single verification failed: {e}")
                return False

    def batch_verify(self, batch: list, trust_scores=None, retries=3) -> dict:
        """
        Batch verifies a list of (statement, proof_obj, [trust_score]) tuples.
        :param batch: List of (statement, proof_obj, [trust_score]) tuples
        :param trust_scores: Optional dict of trust scores for nodes
        :return: Dict mapping index to verification result
        """
        with self.lock:
            if not isinstance(batch, list) or not all(
                isinstance(item, tuple) and len(item) in [2, 3] and isinstance(item[0], str) and isinstance(item[1], dict)
                for item in batch
            ):
                logger.warning(f"Invalid batch input: {batch}")
                raise ValueError("Batch must be a list of (statement, proof_obj, [trust_score]) tuples")

            try:
                batch_hash = hashlib.sha3_512(cbor2.dumps([(item[0], item[1]) for item in batch])).hexdigest()
                cache_key = f"zkp_batch_verify_{batch_hash}"
                cached_results = self.redis_client.get(cache_key)
                if cached_results:
                    logger.debug("Returning cached batch verification results")
                    return json.loads(cached_results)

                results = {}
                for attempt in range(retries):
                    try:
                        # Prepare batch with trust scores
                        batch_with_trust = [
                            (item[0], item[1], item[2] if len(item) == 3 else trust_scores.get(str(idx), 1.0) if trust_scores else 1.0)
                            for idx, item in enumerate(batch)
                        ]

                        # Parallelize verification using multiprocessing
                        with Pool() as pool:
                            verify_tasks = [
                                (idx, item[0], item[1], item[2])
                                for idx, item in enumerate(batch_with_trust)
                            ]
                            results_list = pool.starmap(
                                self._verify_task,
                                [(idx, stmt, proof, trust) for idx, stmt, proof, trust in verify_tasks]
                            )

                        results = {idx: result for idx, result in results_list}

                        # Log to QLDB
                        event_data = {
                            "batch_hash": batch_hash,
                            "batch_size": len(batch),
                            "valid_count": sum(1 for r in results.values() if r),
                            "signature": sign_message(cbor2.dumps({"batch_hash": batch_hash}))
                        }
                        QLDBLogger.log_event("zkp_batch_verify", event_data)

                        # Cache results for 300 seconds
                        self.redis_client.setex(cache_key, 300, json.dumps(results))

                        # Publish to AWS IoT
                        payload = {
                            "batch_hash": batch_hash,
                            "batch_size": len(batch),
                            "valid_count": event_data["valid_count"]
                        }
                        payload_bytes = cbor2.dumps(payload)
                        signature = sign_message(payload_bytes)
                        signed_payload = {'data': payload, 'signature': signature}

                        self.iot_client.publish(
                            topic=f"{IOT_TOPIC_PREFIX}/zkp/batch_verify",
                            qos=1,
                            payload=cbor2.dumps(signed_payload)
                        )

                        logger.info(f"Batch verified {len(batch)} proofs: valid={event_data['valid_count']}")
                        return results
                    except ClientError as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for batch verification: {e}")
                            time.sleep(2 ** attempt)
                        else:
                            logger.error(f"Failed to batch verify after {retries} attempts: {e}")
                            raise
            except Exception as e:
                logger.error(f"zk-SNARK batch verification failed: {e}")
                raise

    def _verify_task(self, idx, statement, proof_obj, trust_score):
        """Helper for parallel verification."""
        try:
            result = self.verify(statement, proof_obj, trust_score)
            return idx, result
        except Exception as e:
            logger.error(f"Verification failed for index {idx}: {e}")
            return idx, False

# Example usage
if __name__ == "__main__":
    pv = ProofVerifier()
    batch = []
    trust_scores = {str(i): 0.8 + i * 0.1 for i in range(3)}  # Mock trust scores
    for i in range(3):
        stmt = f"user compliance {i}"
        wtns = f"witness{i}"
        proof = ZKProof().generate_proof(stmt, wtns)
        batch.append((stmt, proof, trust_scores[str(i)]))
    results = pv.batch_verify(batch, trust_scores)
    print("Batch verification results:", results)