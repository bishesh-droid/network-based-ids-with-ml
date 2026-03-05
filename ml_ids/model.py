import pickle
import os
from enum import Enum

import numpy as np
from scapy.all import IP, TCP, UDP, ICMP
from sklearn.ensemble import RandomForestClassifier

from .logger import ml_ids_logger
from .config import MODEL_PATH, MODEL_VERSION, ANOMALY_THRESHOLD


# ---------------------------------------------------------------------------
# Threat classification
# ---------------------------------------------------------------------------

class ThreatType(Enum):
    """Categorises the probable nature of a flagged packet."""
    NORMAL = "Normal"
    SYN_FLOOD = "Potential SYN Flood"
    SUSPICIOUS_PORT = "Suspicious Destination Port"
    ANOMALOUS_PAYLOAD = "Anomalous Payload Size"
    FRAGMENTATION_ATTACK = "IP Fragmentation Attack"
    ANOMALOUS_TRAFFIC = "Anomalous Traffic"


# Well-known ports commonly abused by malware / remote-access tools
_SUSPICIOUS_PORTS = {23, 445, 1433, 3389, 4444, 5900, 6666, 31337}


def classify_threat(features: np.ndarray, prediction: int) -> ThreatType:
    """
    Applies lightweight heuristics on top of the ML prediction to suggest a
    probable threat category.

    Args:
        features: A (1, N) feature array as returned by extract_features().
        prediction: The binary label from model.predict() — 0 normal, 1 attack.

    Returns:
        A ThreatType enum value.
    """
    if prediction == 0:
        return ThreatType.NORMAL

    feat = features[0]
    pkt_len      = float(feat[0])
    tcp_flags    = int(feat[6])
    dst_port     = int(feat[8])
    ip_frag      = int(feat[10])

    # Fragmentation checked first — it can co-occur with SYN and should take priority
    if ip_frag > 0:
        return ThreatType.FRAGMENTATION_ATTACK

    # Pure SYN (flag value = 2) with a suspiciously large packet
    if tcp_flags == 2 and pkt_len > 80:
        return ThreatType.SYN_FLOOD

    if dst_port in _SUSPICIOUS_PORTS:
        return ThreatType.SUSPICIOUS_PORT

    if pkt_len > 300:
        return ThreatType.ANOMALOUS_PAYLOAD

    return ThreatType.ANOMALOUS_TRAFFIC


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------

def extract_features(packet) -> np.ndarray:
    """
    Extracts a fixed-length numerical feature vector from a Scapy packet.

    Feature index map (13 features):
        0  Packet length (bytes)
        1  IP TTL
        2  Is TCP (0/1)
        3  Is UDP (0/1)
        4  Is ICMP (0/1)
        5  Has Raw payload (0/1)
        6  TCP flags sum  (0 for non-TCP)
        7  Source port    (0 for non-TCP/UDP)
        8  Destination port (0 for non-TCP/UDP)
        9  IP flags field
        10 IP fragment offset
        11 IP header length (ihl, in 4-byte words — normally 5)
        12 IP Type-of-Service / DSCP byte
    """
    has_ip = IP in packet

    features = [
        len(packet),
        packet[IP].ttl  if has_ip else 0,
        1 if TCP  in packet else 0,
        1 if UDP  in packet else 0,
        1 if ICMP in packet else 0,
        1 if packet.haslayer("Raw") else 0,
    ]

    tcp_flags_sum = 0
    src_port = 0
    dst_port = 0

    if TCP in packet:
        tcp_flags_sum = int(packet[TCP].flags)
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif UDP in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    features.extend([
        tcp_flags_sum,
        src_port,
        dst_port,
        int(packet[IP].flags) if has_ip else 0,
        packet[IP].frag       if has_ip else 0,
        (packet[IP].ihl or 5) if has_ip else 0,   # ihl is None until packet is built
        (packet[IP].tos or 0) if has_ip else 0,
    ])

    return np.array(features, dtype=float).reshape(1, -1)


# ---------------------------------------------------------------------------
# Model training / loading
# ---------------------------------------------------------------------------

def _train_dummy_model() -> RandomForestClassifier:
    """
    Trains a RandomForestClassifier on hand-crafted representative samples.

    Feature columns (13):
        [pkt_len, ttl, is_tcp, is_udp, is_icmp, has_raw,
         tcp_flags, src_port, dst_port, ip_flags, ip_frag, ip_ihl, ip_tos]

    Labels: 0 = Normal, 1 = Attack
    """
    ml_ids_logger.info("[*] Training dummy ML model for IDS (conceptual)...")

    X = np.array([
        # ---- Normal traffic ------------------------------------------------
        # Normal HTTP SYN/ACK
        [ 60,  64, 1, 0, 0, 1, 18, 12345,   80, 2, 0, 5,  0],
        # Normal HTTP SYN
        [ 60,  64, 1, 0, 0, 1,  2, 54321,   80, 2, 0, 5,  0],
        # Normal HTTPS SYN
        [ 60,  64, 1, 0, 0, 0,  2, 55000,  443, 2, 0, 5,  0],
        # Normal DNS over UDP
        [ 42,  64, 0, 1, 0, 0,  0,    53, 1234, 0, 0, 5,  0],
        # Normal SSH SYN
        [ 90,  64, 1, 0, 0, 1,  2, 12345,   22, 2, 0, 5,  0],
        # Normal TCP RST
        [ 52,  64, 1, 0, 0, 0,  4, 12345,   80, 2, 0, 5,  0],
        # Normal ICMP echo request (ping)
        [ 84,  64, 0, 0, 1, 0,  0,     0,    0, 0, 0, 5,  0],
        # Normal UDP NTP
        [ 76,  64, 0, 1, 0, 0,  0,   123,  123, 0, 0, 5,  0],
        # Normal FIN/ACK (connection teardown)
        [ 52,  64, 1, 0, 0, 0, 17, 12345,   80, 2, 0, 5,  0],
        # Normal ACK-only
        [ 52,  64, 1, 0, 0, 0, 16, 12345,   80, 2, 0, 5,  0],

        # ---- Attack patterns -----------------------------------------------
        # SYN flood: bare SYN with oversized packet
        [120,  64, 1, 0, 0, 1,  2, 12345,   80, 2, 0, 5,  0],
        # SYN to Telnet (cleartext remote access)
        [ 70,  64, 1, 0, 0, 1,  2, 12345,   23, 2, 0, 5,  0],
        # PSH/ACK with large payload (data exfiltration pattern)
        [400,  64, 1, 0, 0, 1, 24, 12345,   80, 2, 0, 5,  0],
        # SYN to SMB (lateral movement / EternalBlue)
        [100, 128, 1, 0, 0, 1,  2, 12345,  445, 2, 0, 5,  0],
        # Fragmented packet (evasion technique)
        [400,  32, 1, 0, 0, 1,  2, 45678,  123, 2, 1, 5,  0],
        # SYN to RDP (brute-force / ransomware lateral movement)
        [ 66,  64, 1, 0, 0, 0,  2, 43210, 3389, 2, 0, 5,  0],
        # SYN to reverse-shell port (4444 — common Metasploit default)
        [ 66,  64, 1, 0, 0, 0,  2, 55555, 4444, 2, 0, 5,  0],
        # ICMP flood: oversized echo request
        [1500, 64, 0, 0, 1, 1,  0,     0,    0, 0, 0, 5,  0],
        # Unusual ToS (high-priority marking — possible covert channel)
        [ 60,  64, 1, 0, 0, 0,  2, 12345,   80, 2, 0, 5, 48],
        # Very high payload UDP (amplification / exfiltration)
        [900,  64, 0, 1, 0, 1,  0,  9999,   53, 0, 0, 5,  0],
    ])

    y = np.array([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  # Normal (10 samples)
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  # Attack (10 samples)
    ])

    model = RandomForestClassifier(n_estimators=50, random_state=42)
    model.fit(X, y)
    ml_ids_logger.info("[*] Dummy ML model trained.")
    return model


def load_model(model_path: str = MODEL_PATH) -> RandomForestClassifier:
    """
    Loads a pre-trained ML model from disk.

    If the file is missing or was built against a different feature schema
    (MODEL_VERSION mismatch), a fresh dummy model is trained and saved.

    Args:
        model_path: Path to the pickled model file.
    """
    if os.path.exists(model_path):
        try:
            with open(model_path, "rb") as f:
                saved = pickle.load(f)

            if isinstance(saved, dict) and saved.get("version") == MODEL_VERSION:
                ml_ids_logger.info(f"[*] ML model v{MODEL_VERSION} loaded from {model_path}.")
                return saved["model"]
            else:
                ml_ids_logger.warning(
                    f"[*] Model at {model_path} is outdated or has an incompatible "
                    f"schema (expected version {MODEL_VERSION}). Retraining..."
                )
        except Exception as e:
            ml_ids_logger.warning(f"[*] Could not load model from {model_path}: {e}. Retraining...")
    else:
        ml_ids_logger.warning(
            f"[*] No model found at {model_path}. Training a dummy model for demonstration."
        )

    model = _train_dummy_model()
    try:
        with open(model_path, "wb") as f:
            pickle.dump({"version": MODEL_VERSION, "model": model}, f)
        ml_ids_logger.info(f"[*] Dummy ML model (v{MODEL_VERSION}) saved to {model_path}.")
    except Exception as e:
        ml_ids_logger.error(f"[ERROR] Could not save dummy model: {e}")

    return model
