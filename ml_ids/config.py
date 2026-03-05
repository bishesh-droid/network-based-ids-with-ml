# ml_ids/config.py

"""
Configuration for the ML-based NIDS.
"""

import os


# Network interface to sniff on
NETWORK_INTERFACE = "eth0"

# Path to the pre-trained ML model
MODEL_PATH = "ml_model.pkl"

# Path to the log file
LOG_FILE = "logs/ml_ids.log"

# Verbosity level for console output
VERBOSE_CONSOLE_OUTPUT = True

# Internal model version — bump this when feature schema changes to trigger retraining
MODEL_VERSION = "1.1"

# Minimum anomaly probability (0.0–1.0) required to flag a packet as anomalous.
# Only used when the model supports predict_proba (e.g. RandomForestClassifier).
ANOMALY_THRESHOLD = 0.5
