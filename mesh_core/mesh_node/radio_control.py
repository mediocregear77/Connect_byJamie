import threading
import logging
from dotenv import load_dotenv
import os
import cbor2
import boto3
from botocore.exceptions import ClientError
from audit_core.audit_log.qldb_logger import QLDBLogger
from security_core.pqc.dilithium import sign_message
import numpy as np
from scipy.fft import fft

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/radio_control.log')
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')
IOT_TOPIC = os.getenv('IOT_TOPIC', 'mesh/radio')
AVAILABLE_MODES = os.getenv('RADIO_MODES', 'LoRa,BLE,WiFi-Direct,Shortwave').split(',')
DEFAULT_FREQUENCY = float(os.getenv('DEFAULT_FREQUENCY', 868.0))
DEFAULT_POWER = int(os.getenv('DEFAULT_POWER', 10))

class RadioController:
    def __init__(self, node_id):
        self.node_id = node_id
        self.current_mode = "LoRa"
        self.available_modes = AVAILABLE_MODES
        self.frequency = DEFAULT_FREQUENCY  # MHz default for LoRa
        self.power_level = DEFAULT_POWER  # dBm
        self.status = "IDLE"
        self.lock = threading.Lock()
        self.iot_client = boto3.client('iot-data', region_name=AWS_REGION)

    def set_mode(self, mode):
        """Set radio mode with validation and QLDB logging."""
        with self.lock:
            try:
                if mode not in self.available_modes:
                    logger.warning(f"Unsupported radio mode: {mode}")
                    return False
                self.current_mode = mode
                self.status = "CONFIGURED"
                
                # Log to QLDB
                event_data = {"node_id": self.node_id, "mode": mode}
                signature = sign_message(cbor2.dumps(event_data))
                QLDBLogger.log_event("radio_mode_change", {**event_data, "signature": signature})
                
                logger.info(f"Switched radio mode to {mode}")
                return True
            except Exception as e:
                logger.error(f"Failed to set mode {mode}: {e}")
                return False

    def tune_frequency(self, freq):
        """Tune radio frequency with QLDB logging."""
        with self.lock:
            try:
                self.frequency = float(freq)
                self.status = "FREQUENCY_SET"
                
                # Log to QLDB
                event_data = {"node_id": self.node_id, "frequency": self.frequency}
                signature = sign_message(cbor2.dumps(event_data))
                QLDBLogger.log_event("radio_frequency_tune", {**event_data, "signature": signature})
                
                logger.info(f"Tuned frequency to {freq} MHz")
                return True
            except ValueError as e:
                logger.error(f"Invalid frequency value: {e}")
                return False
            except Exception as e:
                logger.error(f"Failed to tune frequency {freq}: {e}")
                return False

    def set_power(self, dbm):
        """Set transmit power with QLDB logging."""
        with self.lock:
            try:
                self.power_level = int(dbm)
                
                # Log to QLDB
                event_data = {"node_id": self.node_id, "power_level": self.power_level}
                signature = sign_message(cbor2.dumps(event_data))
                QLDBLogger.log_event("radio_power_set", {**event_data, "signature": signature})
                
                logger.info(f"Set transmit power to {dbm} dBm")
                return True
            except ValueError as e:
                logger.error(f"Invalid power value: {e}")
                return False
            except Exception as e:
                logger.error(f"Failed to set power {dbm}: {e}")
                return False

    def scan_for_interference(self):
        """Scan for interference using FFT analysis and AWS IoT telemetry."""
        try:
            # Fetch signal data from AWS IoT (simulated as random samples)
            response = self.iot_client.get_thing_shadow(thingName=self.node_id)
            shadow = json.loads(response['payload'].read())['state']['reported']
            signal_samples = shadow.get('radio_signal', np.random.randn(1024))  # Mock data

            # Perform FFT analysis
            freq_spectrum = np.abs(fft(signal_samples))
            interference_threshold = np.mean(freq_spectrum) + 2 * np.std(freq_spectrum)
            detected = any(freq_spectrum > interference_threshold)
            
            # Log to QLDB
            event_data = {"node_id": self.node_id, "interference_detected": detected}
            signature = sign_message(cbor2.dumps(event_data))
            QLDBLogger.log_event("radio_interference_scan", {**event_data, "signature": signature})
            
            logger.info(f"Interference detected: {detected}")
            return detected
        except ClientError as e:
            logger.error(f"AWS IoT shadow error: {e}")
            return False
        except Exception as e:
            logger.error(f"Failed to scan for interference: {e}")
            return False

    def auto_adapt(self):
        """Automatically adapt radio mode/frequency if interference detected."""
        with self.lock:
            try:
                if self.scan_for_interference():
                    old_mode = self.current_mode
                    available_modes = [m for m in self.available_modes if m != old_mode]
                    if not available_modes:
                        logger.warning("No alternative modes available for adaptation")
                        return False
                    new_mode = available_modes[0]  # Choose first alternative (production: use metrics)
                    self.set_mode(new_mode)
                    
                    # Adjust frequency based on mode (example ranges)
                    mode_freqs = {"LoRa": 868.0, "BLE": 2402.0, "WiFi-Direct": 2412.0, "Shortwave": 7.0}
                    self.tune_frequency(mode_freqs.get(new_mode, self.frequency))
                    
                    logger.info(f"Auto-adapted from {old_mode} to {new_mode}")
                    return True
                return False
            except Exception as e:
                logger.error(f"Failed to auto-adapt: {e}")
                return False

    def transmit(self, data):
        """Transmit data via AWS IoT with PQC signing."""
        with self.lock:
            try:
                # Serialize and sign data
                message_data = {"node_id": self.node_id, "payload": data}
                message_bytes = cbor2.dumps(message_data)
                signature = sign_message(message_bytes)
                signed_message = {"data": message_data, "signature": signature}

                # Publish to AWS IoT
                self.iot_client.publish(
                    topic=f'{IOT_TOPIC}/{self.node_id}',
                    qos=1,
                    payload=cbor2.dumps(signed_message)
                )
                
                # Log to QLDB
                QLDBLogger.log_event("radio_transmit", {
                    "node_id": self.node_id,
                    "data_size": len(data),
                    "mode": self.current_mode,
                    "signature": signature
                })
                
                logger.info(f"Transmitting data ({len(data)} bytes) via {self.current_mode} @ {self.frequency} MHz, {self.power_level} dBm")
                return True
            except ClientError as e:
                logger.error(f"AWS IoT transmit error: {e}")
                return False
            except Exception as e:
                logger.error(f"Failed to transmit data: {e}")
                return False

    def receive(self):
        """Listen for incoming data via AWS IoT."""
        with self.lock:
            try:
                # In production: subscribe to IoT topic (handled by IoT Core)
                logger.info(f"Listening on {self.current_mode} @ {self.frequency} MHz")
                return True
            except Exception as e:
                logger.error(f"Failed to receive data: {e}")
                return False