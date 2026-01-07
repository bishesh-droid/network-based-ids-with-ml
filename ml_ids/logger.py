# ml_ids/logger.py

import logging
import os
from .config import LOG_FILE

def setup_logger(log_file=LOG_FILE):
    """
    Configures the logger for the ML-based NIDS.

    Args:
        log_file (str): Path to the log file.
    """
    # Create logs directory if it doesn't exist
    log_dir = os.path.dirname(log_file)
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    # Configure logger
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )

    logger = logging.getLogger("ml_ids")
    return logger

ml_ids_logger = setup_logger()
