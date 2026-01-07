import click
import sys

from .detector import MLIntrusionDetector
from .config import NETWORK_INTERFACE, MODEL_PATH, LOG_FILE

@click.command()
@click.option('--interface', '-i', default=NETWORK_INTERFACE,
              help=f'Network interface to sniff on (default: {NETWORK_INTERFACE}).')
@click.option('--pcap', '-p', type=click.Path(exists=True),
              help='Path to a PCAP file to read packets from instead of live sniffing.')
@click.option('--count', '-c', type=int, default=0,
              help='Number of packets to process (0 for indefinite).')
@click.option('--model-path', '-m', default=MODEL_PATH,
              help=f'Path to the ML model (default: {MODEL_PATH}).')
@click.option('--log-file', '-l', default=LOG_FILE,
              help=f'Path to the log file (default: {LOG_FILE}).')
def main(interface, pcap, count, model_path, log_file):
    """
    A Network-based Intrusion Detection System (NIDS) with Machine Learning.

    Monitors network traffic (live or from PCAP) and uses an ML model
    to detect anomalous activity.
    """
    ml_ids_logger.info("[*] Starting ML-based Intrusion Detection System...")

    # Setup logger
    from .logger import setup_logger
    ml_ids_logger = setup_logger(log_file)

    detector = MLIntrusionDetector(interface=interface, pcap_file=pcap, model_path=model_path)

    # Handle graceful shutdown on Ctrl+C for live sniffing
    if not pcap:
        def signal_handler(sig, frame):
            ml_ids_logger.info("Ctrl+C detected. Shutting down ML IDS...")
            detector.stop()
            sys.exit(0)

        import signal
        signal.signal(signal.SIGINT, signal_handler)

    try:
        detector.start_sniffing(count=count)
    except Exception as e:
        ml_ids_logger.critical(f"[CRITICAL] An unhandled error occurred: {e}")
        sys.exit(1)

    ml_ids_logger.info("[*] ML-based Intrusion Detection System finished.")

if __name__ == '__main__':
    main()
