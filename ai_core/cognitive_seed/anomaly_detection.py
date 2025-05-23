import numpy as np
import logging
import threading
from dotenv import load_dotenv
import os
import redis
import cbor2
from sklearn.ensemble import IsolationForest
from audit_core.audit_log.qldb_logger import QLDBLogger
from security_core.pqc.dilithium import sign_message
import hashlib

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/anomaly_detection.log')
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
THRESHOLD = float(os.getenv('ANOMALY_THRESHOLD', 3.0))
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')

class AnomalyDetector:
    """
    Detects anomalies in node telemetry, model inference, and communications.
    Combines z-score and Isolation Forest for robust detection.
    """

    def __init__(self, threshold=THRESHOLD):
        self.threshold = threshold  # Standard deviation multiplier
        self.lock = threading.Lock()
        self.redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)

    def detect(self, series):
        """
        Detect anomalies using z-score and Isolation Forest.
        :param series: List or np.array of floats (e.g., latency, inference times)
        :return: List of indices where anomalies were detected
        """
        with self.lock:
            if not isinstance(series, (list, np.ndarray)) or len(series) < 2:
                logger.warning(f"Invalid series input: {series}")
                return []

            try:
                arr = np.array(series, dtype=float)
                cache_key = f"anomaly_stats_{hashlib.sha3_512(arr.tobytes()).hexdigest()}"
                cached_stats = self.redis_client.get(cache_key)
                if cached_stats:
                    mean, std = json.loads(cached_stats)
                    logger.debug("Using cached statistics for anomaly detection")
                else:
                    mean = arr.mean()
                    std = arr.std()
                    self.redis_client.setex(cache_key, 300, json.dumps((mean, std)))

                # Z-score detection
                z_scores = np.abs(arr - mean) / std
                z_anomalies = np.where(z_scores > self.threshold)[0]

                # Isolation Forest detection
                X = arr.reshape(-1, 1)
                iso_predictions = self.isolation_forest.fit_predict(X)
                iso_anomalies = np.where(iso_predictions == -1)[0]

                # Combine results (union of anomalies)
                anomalies = np.unique(np.concatenate([z_anomalies, iso_anomalies])).tolist()

                # Log to QLDB
                event_data = {
                    "series_hash": hashlib.sha3_512(arr.tobytes()).hexdigest(),
                    "anomaly_count": len(anomalies),
                    "anomaly_indices": anomalies,
                    "signature": sign_message(cbor2.dumps({"anomaly_count": len(anomalies)}))
                }
                QLDBLogger.log_event("anomaly_detection", event_data)

                logger.info(f"Detected {len(anomalies)} anomalies in series")
                return anomalies
            except Exception as e:
                logger.error(f"Failed to detect anomalies: {e}")
                return []

    def detect_pattern_shift(self, series, window=10):
        """
        Detect abrupt shifts in average value over a moving window.
        :param series: List or np.array of floats
        :param window: Size of moving average window
        :return: List of (start_idx, end_idx, old_mean, new_mean) for each detected shift
        """
        with self.lock:
            if not isinstance(series, (list, np.ndarray)) or len(series) < 2 * window:
                logger.warning(f"Invalid series or window: series_length={len(series)}, window={window}")
                return []

            try:
                arr = np.array(series, dtype=float)
                cache_key = f"pattern_shift_{hashlib.sha3_512(arr.tobytes()).hexdigest()}_{window}"
                cached_shifts = self.redis_client.get(cache_key)
                if cached_shifts:
                    logger.debug("Returning cached pattern shifts")
                    return json.loads(cached_shifts)

                shifts = []
                for i in range(window, len(series) - window):
                    old_window = arr[i-window:i]
                    new_window = arr[i:i+window]
                    old_mean = np.mean(old_window)
                    new_mean = np.mean(new_window)
                    if abs(new_mean - old_mean) > self.threshold * np.std(arr[:i]):
                        shifts.append((i-window, i+window, float(old_mean), float(new_mean)))

                # Log to QLDB
                event_data = {
                    "series_hash": hashlib.sha3_512(arr.tobytes()).hexdigest(),
                    "shift_count": len(shifts),
                    "signature": sign_message(cbor2.dumps({"shift_count": len(shifts)}))
                }
                QLDBLogger.log_event("pattern_shift_detection", event_data)

                # Cache shifts for 300 seconds
                self.redis_client.setex(cache_key, 300, json.dumps(shifts))
                logger.info(f"Detected {len(shifts)} pattern shifts in series")
                return shifts
            except Exception as e:
                logger.error(f"Failed to detect pattern shifts: {e}")
                return []

# Example usage
if __name__ == "__main__":
    detector = AnomalyDetector(threshold=3.0)
    latency_series = [10, 12, 11, 50, 13, 14, 100, 15]
    anomalies = detector.detect(latency_series)
    print(f"Anomalies at indices: {anomalies}")
    inference_series = [1.0, 1.1, 1.0, 2.0, 2.1, 2.0, 1.0, 1.1]
    pattern_shifts = detector.detect_pattern_shift(inference_series, window=3)
    print(f"Pattern shifts: {pattern_shifts}")