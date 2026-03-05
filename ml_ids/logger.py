# ml_ids/logger.py

import logging
import os

from .config import LOG_FILE


def setup_logger(log_file=LOG_FILE):
    """
    Configures and returns the 'ml_ids' logger.

    Safe to call multiple times — handlers are only added once to prevent
    duplicate log entries (the default pitfall with logging.basicConfig).

    Args:
        log_file (str): Path to the log file.
    """
    logger = logging.getLogger("ml_ids")

    # If handlers already exist, the logger is already configured.
    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG)

    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    # File handler
    log_dir = os.path.dirname(log_file)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir)

    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    return logger


ml_ids_logger = setup_logger()
