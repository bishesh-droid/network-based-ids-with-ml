import signal
import sys

import click

from .logger import ml_ids_logger, setup_logger
from .detector import MLIntrusionDetector
from .config import NETWORK_INTERFACE, MODEL_PATH, LOG_FILE


@click.command()
@click.option("--interface", "-i", default=NETWORK_INTERFACE,
              help=f"Network interface to sniff on (default: {NETWORK_INTERFACE}).")
@click.option("--pcap", "-p", type=click.Path(exists=True),
              help="Path to a PCAP file to analyse instead of live sniffing.")
@click.option("--count", "-c", type=int, default=0,
              help="Number of packets to process (0 = unlimited).")
@click.option("--model-path", "-m", default=MODEL_PATH,
              help=f"Path to the ML model file (default: {MODEL_PATH}).")
@click.option("--log-file", "-l", default=LOG_FILE,
              help=f"Destination log file (default: {LOG_FILE}).")
@click.option("--verbose", "-v", is_flag=True, default=False,
              help="Enable DEBUG-level console output.")
def main(interface, pcap, count, model_path, log_file, verbose):
    """
    Network-based Intrusion Detection System (NIDS) with Machine Learning.

    Monitors traffic (live or from a PCAP file) and uses a Random Forest
    classifier to flag anomalous packets, categorising them by threat type.
    """
    # Re-initialise the logger with the caller-supplied log file path and
    # verbosity level.  This must happen before any detector code runs.
    import logging
    logger = setup_logger(log_file)
    if verbose:
        for handler in logger.handlers:
            if isinstance(handler, logging.StreamHandler) and \
               not isinstance(handler, logging.FileHandler):
                handler.setLevel(logging.DEBUG)

    ml_ids_logger.info("[*] Starting ML-based Intrusion Detection System...")

    detector = MLIntrusionDetector(
        interface=interface,
        pcap_file=pcap,
        model_path=model_path,
    )

    # Register Ctrl+C handler for live sniffing so we still print stats.
    if not pcap:
        def _signal_handler(sig, frame):
            ml_ids_logger.info("\n[*] Ctrl+C detected — shutting down ML IDS...")
            detector.stop()
            sys.exit(0)

        signal.signal(signal.SIGINT, _signal_handler)

    try:
        detector.start_sniffing(count=count)
    except Exception as e:
        ml_ids_logger.critical(f"[CRITICAL] An unhandled error occurred: {e}")
        sys.exit(1)

    ml_ids_logger.info("[*] ML-based Intrusion Detection System finished.")


if __name__ == "__main__":
    main()
