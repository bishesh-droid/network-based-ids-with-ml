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
    This is a simplified feature set for demonstration purposes.

    Features:
    1. Packet Length (bytes)
    2. Is TCP (1/0)
    3. Is UDP (1/0)
    4. Is ICMP (1/0)
    5. Has Raw Layer (1/0)
    6. TCP Flags (SYN, ACK, FIN, RST, PSH, URG - sum of their values)
    7. Source Port (if TCP/UDP, else 0)
    8. Destination Port (if TCP/UDP, else 0)
    """
    features = [
        len(packet), # Packet Length
        1 if TCP in packet else 0, # Is TCP
        1 if UDP in packet else 0, # Is UDP
        1 if ICMP in packet else 0, # Is ICMP
        1 if packet.haslayer('Raw') else 0, # Has Raw Layer
    ]

    tcp_flags_sum = 0
    src_port = 0
    dst_port = 0

    if TCP in packet:
        tcp_flags = packet[TCP].flags
        # Sum of flag values (S=2, A=16, F=1, R=4, P=8, U=32)
        tcp_flags_sum = int(tcp_flags)
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif UDP in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    features.extend([
        tcp_flags_sum,
        src_port,
        dst_port
    ])

    return np.array(features).reshape(1, -1) # Reshape for single sample prediction


def _train_dummy_model():
    """
    Trains a very simple Decision Tree Classifier with hardcoded data.
    This simulates a pre-trained model for demonstration.
    
    Features used:
    [Packet Length, Is TCP, Is UDP, Is ICMP, Has Raw Layer, TCP Flags Sum, Source Port, Destination Port]
    
    Labels: 0 = Normal, 1 = Attack
    """
    ml_ids_logger.info("[*] Training dummy ML model for IDS (conceptual)...")
    # Example data: Normal traffic vs. simple attack patterns
    X = np.array([
        [60, 1, 0, 0, 1, 18, 12345, 80],  # Normal HTTP SYN/ACK
        [60, 1, 0, 0, 1, 2, 54321, 80],   # Normal HTTP SYN
        [42, 0, 1, 0, 0, 0, 53, 12345],   # Normal DNS UDP
        [90, 1, 0, 0, 1, 2, 12345, 22],   # Normal SSH SYN
        
        # Attack patterns (simplified)
        [100, 1, 0, 0, 1, 2, 12345, 80],  # SYN packet with large payload (potential flood/exploit)
        [70, 1, 0, 0, 1, 2, 12345, 23],   # SYN to Telnet (often scanned)
        [150, 1, 0, 0, 1, 24, 12345, 80], # PSH/ACK with large payload (potential XSS/SQLi)
        [60, 0, 0, 1, 0, 0, 0, 0],        # ICMP packet (could be part of scan/DoS)
    ])
    y = np.array([0, 0, 0, 0, 1, 1, 1, 1]) # 0=Normal, 1=Attack

    model = DecisionTreeClassifier(random_state=42)
    model.fit(X, y)
    ml_ids_logger.info("[*] Dummy ML model trained.")
    return model

def load_model():
    """
    Loads a pre-trained ML model. If not found, a dummy model is trained and saved.
    """
    if os.path.exists(MODEL_PATH):
        ml_ids_logger.info(f"[*] Loading ML model from {MODEL_PATH}...")
        with open(MODEL_PATH, 'rb') as f:
            model = pickle.load(f)
        ml_ids_logger.info("[*] ML model loaded.")
        return model
    else:
        ml_ids_logger.warning("[*] ML model not found. Training a dummy model for demonstration.")
        model = _train_dummy_model()
        try:
            with open(MODEL_PATH, 'wb') as f:
                pickle.dump(model, f)
            ml_ids_logger.info(f"[*] Dummy ML model saved to {MODEL_PATH}.")
        except Exception as e:
            ml_ids_logger.error(f"[ERROR] Could not save dummy model: {e}")
        return model
