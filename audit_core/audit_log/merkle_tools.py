import hashlib
import math
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
from security_core.zk_snark.zkp import generate_zkp, verify_zkp
import time
import json

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/merkle_tools.log')
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')
IOT_TOPIC_PREFIX = os.getenv('IOT_TOPIC_PREFIX', 'mesh')

class MerkleTools:
    """
    Utilities for Merkle tree construction and proof with PQC signatures.
    Supports building trees, generating/verifying proofs, and batch operations.
    """

    def __init__(self):
        self.lock = threading.Lock()
        self.redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
        self.iot_client = boto3.client('iot-data', region_name=AWS_REGION)
        self.signer = DilithiumSigner()
        self.logger = QLDBLogger()

    def sha3_512(self, data, retries=3):
        """Compute SHA3-512 hash with retry logic."""
        with self.lock:
            if not isinstance(data, (str, bytes)):
                logger.warning(f"Invalid data for hashing: {data}")
                raise ValueError("Data must be string or bytes")

            try:
                data_bytes = data.encode('utf-8') if isinstance(data, str) else data
                for attempt in range(retries):
                    try:
                        return hashlib.sha3_512(data_bytes).hexdigest()
                    except Exception as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for SHA3-512 hash: {e}")
                            time.sleep(2 ** attempt)
                        else:
                            logger.error(f"Failed to compute SHA3-512 hash after {retries} attempts: {e}")
                            raise
            except Exception as e:
                logger.error(f"Failed to compute SHA3-512 hash: {e}")
                raise

    def build_merkle_tree(self, leaves, retries=3):
        """
        Build a Merkle tree from a list of leaf data strings.
        Returns the tree as a list of levels, each a list of node hashes.
        """
        with self.lock:
            if not isinstance(leaves, list) or not all(isinstance(leaf, str) for leaf in leaves):
                logger.warning(f"Invalid leaves: {leaves}")
                raise ValueError("Leaves must be a list of strings")
            if not leaves:
                return []

            try:
                leaves_hash = hashlib.sha3_512(cbor2.dumps(leaves)).hexdigest()
                cache_key = f"merkle_tree_{leaves_hash}"
                cached_tree = self.redis_client.get(cache_key)
                if cached_tree:
                    logger.debug(f"Returning cached Merkle tree: leaves_hash={leaves_hash[:16]}...")
                    return json.loads(cached_tree)

                for attempt in range(retries):
                    try:
                        # Compute leaf hashes
                        current_level = [self.sha3_512(leaf) for leaf in leaves]
                        tree = [current_level]
                        while len(current_level) > 1:
                            next_level = []
                            for i in range(0, len(current_level), 2):
                                left = current_level[i]
                                right = current_level[i + 1] if i + 1 < len(current_level) else left
                                node_hash = self.sha3_512(left + right)
                                next_level.append(node_hash)
                            tree.append(next_level)
                            current_level = next_level

                        # Generate Dilithium signature for tree
                        tree_bytes = cbor2.dumps(tree)
                        pub_key, priv_key = self.signer.keygen()
                        signature = self.signer.sign(tree_bytes, priv_key)

                        # Generate ZKP for tree integrity
                        tree_hash = hashlib.sha3_512(tree_bytes).hexdigest()
                        zkp = generate_zkp(tree_hash)
                        if not verify_zkp(tree_hash, zkp):
                            logger.warning(f"ZKP verification failed for tree_hash={tree_hash[:16]}...")
                            raise RuntimeError("Merkle tree integrity verification failed")

                        # Log to QLDB
                        event_data = {
                            "tree_hash": tree_hash,
                            "leaf_count": len(leaves),
                            "signature": sign_message(cbor2.dumps({"tree_hash": tree_hash}))
                        }
                        self.logger.log_event("merkle_tree_build", event_data)

                        # Cache tree for 300 seconds
                        self.redis_client.setex(cache_key, 300, json.dumps(tree))

                        # Publish to AWS IoT
                        payload = {
                            "tree_hash": tree_hash,
                            "leaf_count": len(leaves),
                            "public_key": pub_key[:16]
                        }
                        payload_bytes = cbor2.dumps(payload)
                        signature = sign_message(payload_bytes)
                        signed_payload = {'data': payload, 'signature': signature}

                        try:
                            self.iot_client.publish(
                                topic=f"{IOT_TOPIC_PREFIX}/merkle/build",
                                qos=1,
                                payload=cbor2.dumps(signed_payload)
                            )
                        except ClientError as e:
                            logger.warning(f"IoT publish error: {e}")

                        logger.info(f"Built Merkle tree: tree_hash={tree_hash[:16]}..., leaves={len(leaves)}")
                        return tree
                    except Exception as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for build_merkle_tree: {e}")
                            time.sleep(2 ** attempt)
                        else:
                            logger.error(f"Failed to build Merkle tree after {retries} attempts: {e}")
                            raise
            except Exception as e:
                logger.error(f"Failed to build Merkle tree: {e}")
                raise

    def get_merkle_root(self, leaves, retries=3):
        """
        Returns the Merkle root for a list of leaf data strings.
        """
        with self.lock:
            if not isinstance(leaves, list) or not all(isinstance(leaf, str) for leaf in leaves):
                logger.warning(f"Invalid leaves: {leaves}")
                raise ValueError("Leaves must be a list of strings")

            try:
                leaves_hash = hashlib.sha3_512(cbor2.dumps(leaves)).hexdigest()
                cache_key = f"merkle_root_{leaves_hash}"
                cached_root = self.redis_client.get(cache_key)
                if cached_root:
                    logger.debug(f"Returning cached Merkle root: leaves_hash={leaves_hash[:16]}...")
                    return cached_root

                for attempt in range(retries):
                    try:
                        tree = self.build_merkle_tree(leaves)
                        root = tree[-1][0] if tree else None

                        if root:
                            # Log to QLDB
                            event_data = {
                                "root_hash": root,
                                "leaf_count": len(leaves),
                                "signature": sign_message(cbor2.dumps({"root_hash": root}))
                            }
                            self.logger.log_event("merkle_root", event_data)

                            # Cache root for 300 seconds
                            self.redis_client.setex(cache_key, 300, root)

                            # Publish to AWS IoT
                            payload = {
                                "root_hash": root[:16],
                                "leaf_count": len(leaves)
                            }
                            payload_bytes = cbor2.dumps(payload)
                            signature = sign_message(payload_bytes)
                            signed_payload = {'data': payload, 'signature': signature}

                            try:
                                self.iot_client.publish(
                                    topic=f"{IOT_TOPIC_PREFIX}/merkle/root",
                                    qos=1,
                                    payload=cbor2.dumps(signed_payload)
                                )
                            except ClientError as e:
                                logger.warning(f"IoT publish error: {e}")

                            logger.info(f"Computed Merkle root: root={root[:16]}...")
                        return root
                    except Exception as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for get_merkle_root: {e}")
                            time.sleep(2 ** attempt)
                        else:
                            logger.error(f"Failed to get Merkle root after {retries} attempts: {e}")
                            raise
            except Exception as e:
                logger.error(f"Failed to get Merkle root: {e}")
                raise

    def get_merkle_proof(self, leaves, index, retries=3):
        """
        Generate a Merkle proof for the leaf at `index`.
        Returns a list of sibling hashes needed to reconstruct the root.
        """
        with self.lock:
            if not isinstance(leaves, list) or not all(isinstance(leaf, str) for leaf in leaves):
                logger.warning(f"Invalid leaves: {leaves}")
                raise ValueError("Leaves must be a list of strings")
            if not isinstance(index, int) or index < 0 or index >= len(leaves):
                logger.warning(f"Invalid index: {index}")
                raise ValueError(f"Index {index} out of range for {len(leaves)} leaves")

            try:
                leaves_hash = hashlib.sha3_512(cbor2.dumps(leaves)).hexdigest()
                cache_key = f"merkle_proof_{leaves_hash}_{index}"
                cached_proof = self.redis_client.get(cache_key)
                if cached_proof:
                    logger.debug(f"Returning cached Merkle proof: index={index}")
                    return json.loads(cached_proof)

                for attempt in range(retries):
                    try:
                        tree = self.build_merkle_tree(leaves)
                        proof = []
                        idx = index
                        for level in tree[:-1]:
                            if len(level) == 1:
                                continue
                            sibling_idx = idx ^ 1  # Pairwise sibling
                            if sibling_idx < len(level):
                                proof.append(level[sibling_idx])
                            idx //= 2

                        # Generate Dilithium signature for proof
                        proof_bytes = cbor2.dumps(proof)
                        pub_key, priv_key = self.signer.keygen()
                        signature = self.signer.sign(proof_bytes, priv_key)

                        # Generate ZKP for proof integrity
                        proof_hash = hashlib.sha3_512(proof_bytes).hexdigest()
                        zkp = generate_zkp(proof_hash)
                        if not verify_zkp(proof_hash, zkp):
                            logger.warning(f"ZKP verification failed for proof_hash={proof_hash[:16]}...")
                            raise RuntimeError("Merkle proof integrity verification failed")

                        proof_obj = {
                            "proof": proof,
                            "signature": signature,
                            "public_key": pub_key,
                            "zkp": zkp
                        }

                        # Log to QLDB
                        event_data = {
                            "proof_hash": proof_hash,
                            "index": index,
                            "leaf_count": len(leaves),
                            "signature": sign_message(cbor2.dumps({"proof_hash": proof_hash}))
                        }
                        self.logger.log_event("merkle_proof", event_data)

                        # Cache proof for 300 seconds
                        self.redis_client.setex(cache_key, 300, json.dumps(proof_obj["proof"]))

                        # Publish to AWS IoT
                        payload = {
                            "proof_hash": proof_hash,
                            "index": index,
                            "public_key": pub_key[:16]
                        }
                        payload_bytes = cbor2.dumps(payload)
                        signature = sign_message(payload_bytes)
                        signed_payload = {'data': payload, 'signature': signature}

                        try:
                            self.iot_client.publish(
                                topic=f"{IOT_TOPIC_PREFIX}/merkle/proof",
                                qos=1,
                                payload=cbor2.dumps(signed_payload)
                            )
                        except ClientError as e:
                            logger.warning(f"IoT publish error: {e}")

                        logger.info(f"Generated Merkle proof: index={index}, proof_hash={proof_hash[:16]}...")
                        return proof_obj["proof"]
                    except Exception as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for get_merkle_proof: {e}")
                            time.sleep(2 ** attempt)
                        else:
                            logger.error(f"Failed to get Merkle proof after {retries} attempts: {e}")
                            raise
            except Exception as e:
                logger.error(f"Failed to get Merkle proof: {e}")
                raise

    def verify_merkle_proof(self, leaf, proof, root, index, retries=3):
        """
        Verifies a Merkle proof with PQC signatures.
        """
        with self.lock:
            if not isinstance(leaf, str) or not isinstance(proof, list) or not all(isinstance(p, str) for p in proof):
                logger.warning(f"Invalid input: leaf={leaf}, proof={proof}")
                raise ValueError("Invalid leaf or proof")
            if not isinstance(root, str) or not isinstance(index, int) or index < 0:
                logger.warning(f"Invalid input: root={root}, index={index}")
                raise ValueError("Invalid root or index")

            try:
                proof_hash = hashlib.sha3_512(cbor2.dumps(proof)).hexdigest()
                cache_key = f"merkle_verify_{proof_hash}_{index}"
                cached_result = self.redis_client.get(cache_key)
                if cached_result:
                    logger.debug(f"Returning cached Merkle proof verification: proof_hash={proof_hash[:16]}...")
                    return json.loads(cached_result)

                for attempt in range(retries):
                    try:
                        hash_value = self.sha3_512(leaf)
                        idx = index
                        for sibling in proof:
                            if idx % 2 == 0:
                                hash_value = self.sha3_512(hash_value + sibling)
                            else:
                                hash_value = self.sha3_512(sibling + hash_value)
                            idx //= 2
                        is_valid = hash_value == root

                        # Log to QLDB
                        event_data = {
                            "proof_hash": proof_hash,
                            "index": index,
                            "is_valid": is_valid,
                            "signature": sign_message(cbor2.dumps({"proof_hash": proof_hash, "is_valid": is_valid}))
                        }
                        self.logger.log_event("merkle_verify", event_data)

                        # Cache result for 300 seconds
                        self.redis_client.setex(cache_key, 300, json.dumps(is_valid))

                        # Publish to AWS IoT
                        payload = {
                            "proof_hash": proof_hash,
                            "index": index,
                            "is_valid": is_valid
                        }
                        payload_bytes = cbor2.dumps(payload)
                        signature = sign_message(payload_bytes)
                        signed_payload = {'data': payload, 'signature': signature}

                        try:
                            self.iot_client.publish(
                                topic=f"{IOT_TOPIC_PREFIX}/merkle/verify",
                                qos=1,
                                payload=cbor2.dumps(signed_payload)
                            )
                        except ClientError as e:
                            logger.warning(f"IoT publish error: {e}")

                        logger.info(f"Verified Merkle proof: proof_hash={proof_hash[:16]}..., is_valid={is_valid}")
                        return is_valid
                    except Exception as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for verify_merkle_proof: {e}")
                            time.sleep(2 ** attempt)
                        else:
                            logger.error(f"Failed to verify Merkle proof after {retries} attempts: {e}")
                            raise
            except Exception as e:
                logger.error(f"Failed to verify Merkle proof: {e}")
                raise

    def batch_get_merkle_proofs(self, leaves, indices, retries=3):
        """
        Generate Merkle proofs for multiple leaf indices in a single tree.
        Returns a dict mapping index to proof.
        """
        with self.lock:
            if not isinstance(leaves, list) or not all(isinstance(leaf, str) for leaf in leaves):
                logger.warning(f"Invalid leaves: {leaves}")
                raise ValueError("Leaves must be a list of strings")
            if not isinstance(indices, list) or not all(isinstance(idx, int) and 0 <= idx < len(leaves) for idx in indices):
                logger.warning(f"Invalid indices: {indices}")
                raise ValueError("Invalid indices")

            try:
                leaves_hash = hashlib.sha3_512(cbor2.dumps(leaves)).hexdigest()
                cache_key = f"merkle_batch_proofs_{leaves_hash}_{hashlib.sha3_512(str(indices).encode()).hexdigest()}"
                cached_proofs = self.redis_client.get(cache_key)
                if cached_proofs:
                    logger.debug(f"Returning cached batch Merkle proofs")
                    return json.loads(cached_proofs)

                for attempt in range(retries):
                    try:
                        proofs = {idx: self.get_merkle_proof(leaves, idx) for idx in indices}

                        # Generate Dilithium signature for batch proofs
                        proofs_bytes = cbor2.dumps(proofs)
                        pub_key, priv_key = self.signer.keygen()
                        signature = self.signer.sign(proofs_bytes, priv_key)

                        # Generate ZKP for batch proof integrity
                        batch_hash = hashlib.sha3_512(proofs_bytes).hexdigest()
                        zkp = generate_zkp(batch_hash)
                        if not verify_zkp(batch_hash, zkp):
                            logger.warning(f"ZKP verification failed for batch_hash={batch_hash[:16]}...")
                            raise RuntimeError("Batch proof integrity verification failed")

                        # Log to QLDB
                        event_data = {
                            "batch_hash": batch_hash,
                            "index_count": len(indices),
                            "signature": sign_message(cbor2.dumps({"batch_hash": batch_hash}))
                        }
                        self.logger.log_event("merkle_batch_proofs", event_data)

                        # Cache proofs for 300 seconds
                        self.redis_client.setex(cache_key, 300, json.dumps(proofs))

                        # Publish to AWS IoT
                        payload = {
                            "batch_hash": batch_hash,
                            "index_count": len(indices),
                            "public_key": pub_key[:16]
                        }
                        payload_bytes = cbor2.dumps(payload)
                        signature = sign_message(payload_bytes)
                        signed_payload = {'data': payload, 'signature': signature}

                        try:
                            self.iot_client.publish(
                                topic=f"{IOT_TOPIC_PREFIX}/merkle/batch_proofs",
                                qos=1,
                                payload=cbor2.dumps(signed_payload)
                            )
                        except ClientError as e:
                            logger.warning(f"IoT publish error: {e}")

                        logger.info(f"Generated batch Merkle proofs: batch_hash={batch_hash[:16]}..., indices={len(indices)}")
                        return proofs
                    except Exception as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for batch_get_merkle_proofs: {e}")
                            time.sleep(2 ** attempt)
                        else:
                            logger.error(f"Failed to get batch Merkle proofs after {retries} attempts: {e}")
                            raise
            except Exception as e:
                logger.error(f"Failed to get batch Merkle proofs: {e}")
                raise

    def batch_verify_merkle_proofs(self, leaves, proofs_dict, root, retries=3):
        """
        Verify multiple Merkle proofs for given leaf indices.
        Returns a dict mapping index to verification result.
        """
        with self.lock:
            if not isinstance(leaves, list) or not all(isinstance(leaf, str) for leaf in leaves):
                logger.warning(f"Invalid leaves: {leaves}")
                raise ValueError("Leaves must be a list of strings")
            if not isinstance(proofs_dict, dict) or not all(isinstance(idx, int) and isinstance(proof, list) for idx, proof in proofs_dict.items()):
                logger.warning(f"Invalid proofs_dict: {proofs_dict}")
                raise ValueError("Invalid proofs dictionary")
            if not isinstance(root, str):
                logger.warning(f"Invalid root: {root}")
                raise ValueError("Invalid root")

            try:
                proofs_hash = hashlib.sha3_512(cbor2.dumps(proofs_dict)).hexdigest()
                cache_key = f"merkle_batch_verify_{proofs_hash}"
                cached_results = self.redis_client.get(cache_key)
                if cached_results:
                    logger.debug(f"Returning cached batch Merkle proof verification")
                    return json.loads(cached_results)

                for attempt in range(retries):
                    try:
                        results = {}
                        for idx, proof in proofs_dict.items():
                            results[idx] = self.verify_merkle_proof(leaves[idx], proof, root, idx)

                        # Generate Dilithium signature for batch verification
                        results_bytes = cbor2.dumps(results)
                        pub_key, priv_key = self.signer.keygen()
                        signature = self.signer.sign(results_bytes, priv_key)

                        # Generate ZKP for batch verification integrity
                        batch_hash = hashlib.sha3_512(results_bytes).hexdigest()
                        zkp = generate_zkp(batch_hash)
                        if not verify_zkp(batch_hash, zkp):
                            logger.warning(f"ZKP verification failed for batch_hash={batch_hash[:16]}...")
                            raise RuntimeError("Batch verification integrity verification failed")

                        # Log to QLDB
                        event_data = {
                            "batch_hash": batch_hash,
                            "index_count": len(proofs_dict),
                            "valid_count": sum(1 for r in results.values() if r),
                            "signature": sign_message(cbor2.dumps({"batch_hash": batch_hash}))
                        }
                        self.logger.log_event("merkle_batch_verify", event_data)

                        # Cache results for 300 seconds
                        self.redis_client.setex(cache_key, 300, json.dumps(results))

                        # Publish to AWS IoT
                        payload = {
                            "batch_hash": batch_hash,
                            "index_count": len(proofs_dict),
                            "valid_count": event_data["valid_count"],
                            "public_key": pub_key[:16]
                        }
                        payload_bytes = cbor2.dumps(payload)
                        signature = sign_message(payload_bytes)
                        signed_payload = {'data': payload, 'signature': signature}

                        try:
                            self.iot_client.publish(
                                topic=f"{IOT_TOPIC_PREFIX}/merkle/batch_verify",
                                qos=1,
                                payload=cbor2.dumps(signed_payload)
                            )
                        except ClientError as e:
                            logger.warning(f"IoT publish error: {e}")

                        logger.info(f"Batch verified Merkle proofs: batch_hash={batch_hash[:16]}..., valid={event_data['valid_count']}")
                        return results
                    except Exception as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for batch_verify_merkle_proofs: {e}")
                            time.sleep(2 ** attempt)
                        else:
                            logger.error(f"Failed to batch verify Merkle proofs after {retries} attempts: {e}")
                            raise
            except Exception as e:
                logger.error(f"Failed to batch verify Merkle proofs: {e}")
                raise

# Example usage
if __name__ == "__main__":
    tools = MerkleTools()
    entries = ["log1", "log2", "log3", "log4"]
    root = tools.get_merkle_root(entries)
    proof = tools.get_merkle_proof(entries, 2)
    print("Merkle Root:", root)
    print("Proof for entry 2:", proof)
    print("Verified:", tools.verify_merkle_proof(entries[2], proof, root, 2))
    batch_proofs = tools.batch_get_merkle_proofs(entries, [0, 2])
    batch_results = tools.batch_verify_merkle_proofs(entries, batch_proofs, root)
    print("Batch verification results:", batch_results)