import pickle
import os
import numpy as np
from scapy.all import IP, TCP, UDP, ICMP
from sklearn.tree import DecisionTreeClassifier

from .logger import ml_ids_logger
from .config import MODEL_PATH

def extract_features(packet):
    """
    Extracts numerical features from a Scapy packet for ML inference.

    Features:
    1.  Packet Length (bytes)
    2.  Time To Live (TTL)
    3.  Is TCP (1/0)
    4.  Is UDP (1/0)
    5.  Is ICMP (1/0)
    6.  Has Raw Layer (1/0)
    7.  TCP Flags (SYN, ACK, FIN, RST, PSH, URG - sum of their values)
    8.  Source Port (if TCP/UDP, else 0)
    9.  Destination Port (if TCP/UDP, else 0)
    10. IP Flags
    11. IP Fragment Offset
    """
    features = [
        len(packet),
        packet[IP].ttl if IP in packet else 0,
        1 if TCP in packet else 0,
        1 if UDP in packet else 0,
        1 if ICMP in packet else 0,
        1 if packet.haslayer('Raw') else 0,
    ]

    tcp_flags_sum = 0
    src_port = 0
    dst_port = 0

    if TCP in packet:
        tcp_flags = packet[TCP].flags
        tcp_flags_sum = int(tcp_flags)
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif UDP in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    features.extend([
        tcp_flags_sum,
        src_port,
        dst_port,
        packet[IP].flags if IP in packet else 0,
        packet[IP].frag if IP in packet else 0,
    ])

    return np.array(features).reshape(1, -1)


from sklearn.ensemble import RandomForestClassifier
def _train_dummy_model():
    """
    Trains a simple Random Forest Classifier with hardcoded data.
    This simulates a pre-trained model for demonstration.

    Features used:
    [Packet Length, TTL, Is TCP, Is UDP, Is ICMP, Has Raw Layer, TCP Flags Sum, Source Port, Destination Port, IP Flags, IP Fragment Offset]

    Labels: 0 = Normal, 1 = Attack
    """
    ml_ids_logger.info("[*] Training dummy ML model for IDS (conceptual)...")
    # Example data: Normal traffic vs. simple attack patterns
    X = np.array([
        # Normal Traffic
        [60, 64, 1, 0, 0, 1, 18, 12345, 80, 2, 0],   # Normal HTTP SYN/ACK
        [60, 64, 1, 0, 0, 1, 2, 54321, 80, 2, 0],    # Normal HTTP SYN
        [42, 64, 0, 1, 0, 0, 0, 53, 12345, 0, 0],    # Normal DNS UDP
        [90, 64, 1, 0, 0, 1, 2, 12345, 22, 2, 0],    # Normal SSH SYN
        [52, 64, 1, 0, 0, 0, 4, 12345, 80, 2, 0],    # Normal TCP RST
        [80, 64, 0, 0, 1, 0, 0, 0, 0, 0, 0],         # Normal ICMP Echo Request

        # Attack Patterns
        [100, 64, 1, 0, 0, 1, 2, 12345, 80, 2, 0],   # SYN packet with large payload
        [70, 64, 1, 0, 0, 1, 2, 12345, 23, 2, 0],    # SYN to Telnet
        [150, 64, 1, 0, 0, 1, 24, 12345, 80, 2, 0],  # PSH/ACK with large payload
        [60, 64, 0, 0, 1, 0, 0, 0, 0, 0, 0],         # ICMP packet
        [400, 32, 1, 0, 0, 1, 2, 45678, 123, 2, 1],  # Fragmented packet
        [100, 128, 1, 0, 0, 1, 2, 12345, 445, 2, 0], # SYN to SMB
    ])
    y = np.array([0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1]) # 0=Normal, 1=Attack

    model = RandomForestClassifier(random_state=42)
    model.fit(X, y)
    ml_ids_logger.info("[*] Dummy ML model trained.")
    return model

def load_model(model_path=MODEL_PATH):
    """
    Loads a pre-trained ML model. If not found, a dummy model is trained and saved.

    Args:
        model_path (str): Path to the pre-trained ML model.
    """
    if os.path.exists(model_path):
        ml_ids_logger.info(f"[*] Loading ML model from {model_path}...")
        with open(model_path, 'rb') as f:
            model = pickle.load(f)
        ml_ids_logger.info("[*] ML model loaded.")
        return model
    else:
        ml_ids_logger.warning(f"[*] ML model not found at {model_path}. Training a dummy model for demonstration.")
        model = _train_dummy_model()
        try:
            with open(model_path, 'wb') as f:
                pickle.dump(model, f)
            ml_ids_logger.info(f"[*] Dummy ML model saved to {model_path}.")
        except Exception as e:
            ml_ids_logger.error(f"[ERROR] Could not save dummy model: {e}")
        return model
