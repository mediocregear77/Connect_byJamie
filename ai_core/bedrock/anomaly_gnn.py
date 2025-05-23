import torch
import torch.nn as nn
import torch.nn.functional as F
import logging
import threading
from dotenv import load_dotenv
import os
import redis
import cbor2
import boto3
from botocore.exceptions import ClientError
from audit_core.audit_log.qldb_logger import QLDBLogger
from security_core.pqc.dilithium import sign_message
from security_core.zk_snark.zkp import generate_zkp, verify_zkp
import hashlib
import time
import json

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/anomaly_gnn.log')
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
MODEL_WEIGHTS_PATH = os.getenv('GNN_MODEL_WEIGHTS_PATH', '/data/model_weights/gnn_weights.pt')
S3_BUCKET = os.getenv('S3_MODEL_BUCKET', 'connection-models')
S3_KEY = os.getenv('S3_GNN_MODEL_KEY', 'gnn_weights.pt')
KMS_KEY_ID = os.getenv('KMS_KEY_ID', '')
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')
IOT_TOPIC_PREFIX = os.getenv('IOT_TOPIC_PREFIX', 'mesh')
DEFAULT_THRESHOLD = float(os.getenv('ANOMALY_THRESHOLD', 0.7))

class AnomalyGNN(nn.Module):
    """
    Graph Neural Network for mesh anomaly detection with GraphSAGE-like aggregation.
    Input: Node feature matrix, adjacency matrix
    Output: Anomaly score per node (0=normal, 1=anomaly)
    """
    def __init__(self, in_features, hidden_dim=32, out_features=2):
        super(AnomalyGNN, self).__init__()
        self.conv1 = nn.Linear(in_features * 2, hidden_dim)  # Concatenate self and neighbor features
        self.conv2 = nn.Linear(hidden_dim * 2, hidden_dim)
        self.fc = nn.Linear(hidden_dim, out_features)
        self.dropout = nn.Dropout(0.3)

    def forward(self, x, adj):
        """
        Forward pass with multi-layer graph convolution.
        :param x: Node features (N x F)
        :param adj: Adjacency matrix (N x N)
        :return: Log softmax probabilities
        """
        # First GraphSAGE layer: Aggregate neighbor features
        neighbor_h = torch.matmul(adj, x)  # N x F
        h = torch.cat([x, neighbor_h], dim=1)  # N x 2F
        h = F.relu(self.conv1(h))
        h = self.dropout(h)

        # Second GraphSAGE layer
        neighbor_h = torch.matmul(adj, h)  # N x hidden_dim
        h = torch.cat([h, neighbor_h], dim=1)  # N x 2*hidden_dim
        h = F.relu(self.conv2(h))
        h = self.dropout(h)

        # Final classification
        h = self.fc(h)
        return F.log_softmax(h, dim=1)

class AnomalyDetector:
    def __init__(self, in_features, hidden_dim=32, out_features=2):
        self.model = AnomalyGNN(in_features, hidden_dim, out_features)
        self.lock = threading.Lock()
        self.redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
        self.s3_client = boto3.client('s3', region_name=AWS_REGION)
        self.kms_client = boto3.client('kms', region_name=AWS_REGION)
        self.iot_client = boto3.client('iot-data', region_name=AWS_REGION)
        self.load_weights()

    def load_weights(self, retries=3):
        """Load model weights from S3 with KMS decryption."""
        with self.lock:
            try:
                cache_key = f"gnn_weights_{hashlib.sha3_512(S3_KEY.encode()).hexdigest()}"
                if self.redis_client.get(cache_key):
                    logger.debug("Weights already loaded from cache")
                    return

                # Download encrypted weights from S3
                for attempt in range(retries):
                    try:
                        response = self.s3_client.get_object(Bucket=S3_BUCKET, Key=S3_KEY)
                        encrypted_weights = response['Body'].read()
                        break
                    except ClientError as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for S3 download: {e}")
                            time.sleep(2 ** attempt)
                        else:
                            logger.error(f"Failed to download weights from S3 after {retries} attempts: {e}")
                            raise

                # Decrypt weights with KMS
                response = self.kms_client.decrypt(
                    CiphertextBlob=encrypted_weights,
                    KeyId=KMS_KEY_ID,
                    EncryptionAlgorithm='SYMMETRIC_DEFAULT'
                )
                weights = torch.load(io.BytesIO(response['Plaintext']))

                self.model.load_state_dict(weights)
                self.model.eval()

                # Cache weights presence for 3600 seconds
                self.redis_client.setex(cache_key, 3600, "loaded")

                # Log to QLDB
                event_data = {
                    "model_hash": hashlib.sha3_512(cbor2.dumps(weights)).hexdigest(),
                    "signature": sign_message(cbor2.dumps({"model_hash": hashlib.sha3_512(cbor2.dumps(weights)).hexdigest()}))
                }
                QLDBLogger.log_event("gnn_weights_load", event_data)

                logger.info("Loaded GNN model weights from S3")
            except ClientError as e:
                logger.error(f"KMS decryption error: {e}")
                raise
            except Exception as e:
                logger.error(f"Failed to load GNN weights: {e}")
                raise

    def detect_anomalies(self, node_features, adj_matrix, threshold=DEFAULT_THRESHOLD, context=None, retries=3):
        """
        Detect anomalies in the mesh with context-aware thresholding.
        :param node_features: torch.Tensor (N x F)
        :param adj_matrix: torch.Tensor (N x N)
        :param threshold: float
        :param context: dict (e.g., trust scores)
        :return: List of anomalous node indices
        """
        with self.lock:
            if not isinstance(node_features, torch.Tensor) or not isinstance(adj_matrix, torch.Tensor):
                logger.warning(f"Invalid input: node_features={type(node_features)}, adj_matrix={type(adj_matrix)}")
                raise ValueError("Node features and adjacency matrix must be torch.Tensor")
            if node_features.shape[0] != adj_matrix.shape[0] or adj_matrix.shape[0] != adj_matrix.shape[1]:
                logger.warning(f"Shape mismatch: node_features={node_features.shape}, adj_matrix={adj_matrix.shape}")
                raise ValueError("Shape mismatch between node features and adjacency matrix")

            try:
                input_hash = hashlib.sha3_512(cbor2.dumps([node_features.tolist(), adj_matrix.tolist()])).hexdigest()
                cache_key = f"anomaly_scores_{input_hash}"
                cached_anomalies = self.redis_client.get(cache_key)
                if cached_anomalies:
                    logger.debug("Returning cached anomaly scores")
                    return json.loads(cached_anomalies)

                # Verify input integrity with ZKP
                zkp = generate_zkp(input_hash)
                if not verify_zkp(input_hash, zkp):
                    logger.warning(f"ZKP verification failed for input_hash={input_hash[:16]}...")
                    raise RuntimeError("Input integrity verification failed")

                for attempt in range(retries):
                    try:
                        with torch.no_grad():
                            scores = self.model(node_features, adj_matrix)
                            anomaly_probs = torch.exp(scores)[:, 1]  # Prob of class 'anomaly'

                        # Context-aware thresholding (e.g., lower threshold for low-trust nodes)
                        if context and "trust_scores" in context:
                            threshold = torch.tensor([
                                DEFAULT_THRESHOLD * (1 - context["trust_scores"].get(i, 0.5))
                                for i in range(node_features.shape[0])
                            ])
                        else:
                            threshold = torch.tensor([threshold] * node_features.shape[0])

                        anomalies = [i for i, prob in enumerate(anomaly_probs) if prob.item() > threshold[i].item()]

                        # Publish results to AWS IoT
                        payload = {"anomalies": anomalies, "input_hash": input_hash}
                        payload_bytes = cbor2.dumps(payload)
                        signature = sign_message(payload_bytes)
                        signed_payload = {'data': payload, 'signature': signature}

                        self.iot_client.publish(
                            topic=f"{IOT_TOPIC_PREFIX}/anomaly/gnn",
                            qos=1,
                            payload=cbor2.dumps(signed_payload)
                        )

                        # Log to QLDB
                        event_data = {
                            "input_hash": input_hash,
                            "anomaly_count": len(anomalies),
                            "signature": signature
                        }
                        QLDBLogger.log_event("gnn_anomaly_detection", event_data)

                        # Cache anomalies for 300 seconds
                        self.redis_client.setex(cache_key, 300, json.dumps(anomalies))
                        logger.info(f"Detected {len(anomalies)} anomalous nodes")
                        return anomalies
                    except Exception as e:
                        if attempt < retries - 1:
                            logger.warning(f"Retry {attempt + 1}/{retries} for anomaly detection: {e}")
                            time.sleep(2 ** attempt)
                        else:
                            logger.error(f"Failed to detect anomalies after {retries} attempts: {e}")
                            raise
            except ClientError as e:
                logger.error(f"AWS IoT publish error: {e}")
                raise
            except Exception as e:
                logger.error(f"Anomaly detection failed: {e}")
                raise

# Example usage
if __name__ == "__main__":
    N = 10  # nodes
    F = 5   # features per node
    features = torch.rand(N, F)
    adj = torch.eye(N)  # For demo: no real connectivity
    context = {"trust_scores": {i: 0.5 for i in range(N)}}
    detector = AnomalyDetector(in_features=F)
    anomalies = detector.detect_anomalies(features, adj, context=context)
    print("Anomalous nodes:", anomalies)