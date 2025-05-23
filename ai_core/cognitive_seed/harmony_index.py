import numpy as np
import logging
import threading
from dotenv import load_dotenv
import os
import redis
import cbor2
import hashlib
from audit_core.audit_log.qldb_logger import QLDBLogger
from security_core.pqc.dilithium import sign_message

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/harmony_index.log')
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
WEIGHTS = os.getenv('HARMONY_WEIGHTS', '0.4,0.3,0.3').split(',')
WEIGHTS = [float(w) for w in WEIGHTS]
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')

class HarmonyIndex:
    """
    Computes the Cognitive Harmony Index, reflecting communication quality,
    accessibility, and trust for the node or local mesh segment.
    """

    def __init__(self, weights=WEIGHTS):
        self.weights = weights if sum(weights) == 1.0 else [0.4, 0.3, 0.3]
        self.history = []
        self.lock = threading.Lock()
        self.redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)

    def update(self, comprehension_scores, accessibility_scores, trust_scores):
        """
        Updates the Harmony Index based on the latest metrics.
        :param comprehension_scores: List[float] (0.0-1.0)
        :param accessibility_scores: List[float] (0.0-1.0)
        :param trust_scores: List[float] (0.0-1.0)
        :return: Current Harmony Index as float
        """
        with self.lock:
            try:
                # Validate inputs
                for scores in [comprehension_scores, accessibility_scores, trust_scores]:
                    if not isinstance(scores, (list, np.ndarray)) or not all(isinstance(s, (int, float)) and 0.0 <= s <= 1.0 for s in scores):
                        logger.warning(f"Invalid scores: {scores}")
                        return 0.0

                # Normalize and filter outliers
                def normalize(scores):
                    arr = np.array(scores, dtype=float)
                    if len(arr) > 0:
                        q1, q3 = np.percentile(arr, [25, 75])
                        iqr = q3 - q1
                        arr = arr[(arr >= q1 - 1.5 * iqr) & (arr <= q3 + 1.5 * iqr)]
                    return arr.tolist()

                c_scores = normalize(comprehension_scores)
                a_scores = normalize(accessibility_scores)
                t_scores = normalize(trust_scores)

                score = self.compute_index(c_scores, a_scores, t_scores)
                self.history.append(score)

                # Cache history (truncate to last 1000 entries)
                cache_key = "harmony_history"
                self.redis_client.setex(cache_key, 3600, json.dumps(self.history[-1000:]))

                # Log to QLDB
                event_data = {
                    "comprehension_mean": float(np.mean(c_scores)) if c_scores else 0.0,
                    "accessibility_mean": float(np.mean(a_scores)) if a_scores else 0.0,
                    "trust_mean": float(np.mean(t_scores)) if t_scores else 0.0,
                    "harmony_index": score,
                    "signature": sign_message(cbor2.dumps({"harmony_index": score}))
                }
                QLDBLogger.log_event("harmony_index_update", event_data)

                logger.info(f"Updated Harmony Index: {score}")
                return score
            except Exception as e:
                logger.error(f"Failed to update Harmony Index: {e}")
                return 0.0

    def compute_index(self, comprehension, accessibility, trust):
        """
        Weighted average of three core metrics with normalization.
        :param comprehension: List[float]
        :param accessibility: List[float]
        :param trust: List[float]
        :return: Harmony Index float (0.0-1.0)
        """
        try:
            c = np.mean(comprehension) if comprehension else 0.0
            a = np.mean(accessibility) if accessibility else 0.0
            t = np.mean(trust) if trust else 0.0
            index = self.weights[0] * c + self.weights[1] * a + self.weights[2] * t
            score = min(max(float(index), 0.0), 1.0)

            cache_key = f"harmony_index_{hashlib.sha3_512(cbor2.dumps([c, a, t])).hexdigest()}"
            self.redis_client.setex(cache_key, 300, json.dumps(score))
            
            logger.debug(f"Computed Harmony Index: {score}")
            return score
        except Exception as e:
            logger.error(f"Failed to compute Harmony Index: {e}")
            return 0.0

    def trend(self, window=10):
        """
        Returns moving average trend of the Harmony Index.
        :param window: int
        :return: List[float]
        """
        with self.lock:
            if not isinstance(window, int) or window < 1:
                logger.warning(f"Invalid window size: {window}")
                return []

            try:
                cache_key = f"harmony_trend_{window}_{hashlib.sha3_512(np.array(self.history).tobytes()).hexdigest()}"
                cached_trend = self.redis_client.get(cache_key)
                if cached_trend:
                    logger.debug("Returning cached trend")
                    return json.loads(cached_trend)

                if len(self.history) < window:
                    trend = self.history
                else:
                    trend = [float(np.mean(self.history[i-window:i])) for i in range(window, len(self.history)+1)]

                # Cache trend for 300 seconds
                self.redis_client.setex(cache_key, 300, json.dumps(trend))
                
                # Log to QLDB
                event_data = {
                    "window": window,
                    "trend_length": len(trend),
                    "signature": sign_message(cbor2.dumps({"trend_length": len(trend)}))
                }
                QLDBLogger.log_event("harmony_trend", event_data)

                logger.info(f"Computed trend for window={window}: {len(trend)} points")
                return trend
            except Exception as e:
                logger.error(f"Failed to compute trend: {e}")
                return []

# Example usage
if __name__ == "__main__":
    hi = HarmonyIndex()
    index = hi.update([0.8, 0.9], [0.7, 0.8], [1.0, 0.95])
    print(f"Harmony Index: {index}")
    trend = hi.trend(window=10)
    print(f"Trend: {trend}")