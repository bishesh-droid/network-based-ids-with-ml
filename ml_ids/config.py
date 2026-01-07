# ml_ids/config.py

import os


"""
Configuration for the ML-based NIDS.
"""

# Network interface to sniff on
NETWORK_INTERFACE = "eth0"

# Path to the pre-trained ML model
MODEL_PATH = "ml_model.pkl"

# Path to the log file
LOG_FILE = "logs/ml_ids.log"


# Verbosity level for console output
VERBOSE_CONSOLE_OUTPUT = True
