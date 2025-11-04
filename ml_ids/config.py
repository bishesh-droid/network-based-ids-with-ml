# ml_ids/config.py

import os

# Default network interface to sniff on.
# You might need to change this based on your system's configuration.
# Use 'ifconfig' or 'ip addr' on Linux/macOS, 'ipconfig' on Windows to find your interface.
NETWORK_INTERFACE = "eth0" # Example: "eth0", "wlan0", "en0"

# Path for the ML IDS log file
LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'logs')
LOG_FILE = os.path.join(LOG_DIR, 'ml_ids.log')

# Path to the (conceptual) pre-trained ML model file.
# For this project, the model will be a simple hardcoded one in model.py.
MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'model.pkl')

# Verbosity level for console output
VERBOSE_CONSOLE_OUTPUT = True
