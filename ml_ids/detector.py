from scapy.all import sniff, IP, TCP, UDP, ICMP
import numpy as np
import threading

from .logger import ml_ids_logger
from .config import NETWORK_INTERFACE
from .model import load_model, extract_features

class MLIntrusionDetector:
    """
    A Network Intrusion Detection System (NIDS) that uses machine learning
    to detect anomalous network traffic.
    """
    def __init__(self, interface=NETWORK_INTERFACE, pcap_file=None, model_path=None):
        """
        Initializes the MLIntrusionDetector.

        Args:
            interface (str): The network interface to sniff on.
            pcap_file (str, optional): Path to a PCAP file to read packets from instead of live sniffing.
            model_path (str, optional): Path to the pre-trained ML model.
        """
        self.interface = interface
        self.pcap_file = pcap_file
        self.model = load_model(model_path)
        self.stop_event = threading.Event() # For graceful shutdown

        if self.pcap_file:
            ml_ids_logger.info(f"[*] Initialized ML IDS to read from PCAP file: {self.pcap_file}")
        else:
            ml_ids_logger.info(f"[*] Initialized ML IDS on interface: {self.interface}")

    def _get_protocol_name(self, packet):
        """Returns the protocol name from the packet."""
        if TCP in packet:
            return "TCP"
        elif UDP in packet:
            return "UDP"
        elif ICMP in packet:
            return "ICMP"
        else:
            return str(packet[IP].proto)

    def _log_packet_info(self, prediction, src_ip, dst_ip, protocol_name, src_port, dst_port, features):
        """Logs information about the processed packet."""
        log_level = "WARNING" if prediction == 1 else "INFO"
        status = "Anomalous" if prediction == 1 else "Normal"

        message = (
            f"[{status.upper()}] {status} traffic detected!\n"
            f"        Source: {src_ip}:{src_port} -> Destination: {dst_ip}:{dst_port} (Protocol: {protocol_name})\n"
            f"        Features: {features}"
        )

        if log_level == "WARNING":
            ml_ids_logger.warning(message)
        else:
            ml_ids_logger.info(message)

    def _process_packet(self, packet):
        """
        Processes a single captured packet.
        Extracts features and uses the ML model to predict if it's anomalous.
        """
        if IP not in packet:
            ml_ids_logger.debug("Non-IP packet received, skipping.")
            return

        try:
            features = extract_features(packet)
            prediction = self.model.predict(features)[0]

            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol_name = self._get_protocol_name(packet)

            src_port = packet.sport if packet.haslayer(TCP) or packet.haslayer(UDP) else "N/A"
            dst_port = packet.dport if packet.haslayer(TCP) or packet.haslayer(UDP) else "N/A"

            self._log_packet_info(prediction, src_ip, dst_ip, protocol_name, src_port, dst_port, features)

        except Exception as e:
            ml_ids_logger.error(f"[ERROR] Error processing packet: {e}")

    def _sniff_live(self, count):
        """Starts live packet sniffing."""
        ml_ids_logger.info(f"[*] Starting live packet sniffing on {self.interface}...")
        try:
            sniff(iface=self.interface, prn=self._process_packet, store=0, count=count, stop_filter=lambda p: self.stop_event.is_set())
        except Exception as e:
            ml_ids_logger.critical(f"[CRITICAL] Error during live sniffing on {self.interface}: {e}")
            ml_ids_logger.critical("        Ensure you have sufficient permissions (e.g., run as root/administrator) and the interface name is correct.")

    def start_sniffing(self, count=0):
        """
        Starts sniffing network traffic or reading from a PCAP file.

        Args:
            count (int): Number of packets to sniff. 0 means sniff indefinitely.
        """
        if self.pcap_file:
            ml_ids_logger.info(f"[*] Reading packets from PCAP file: {self.pcap_file}...")
            try:
                sniff(offline=self.pcap_file, prn=self._process_packet, store=0, count=count)
            except Exception as e:
                ml_ids_logger.critical(f"[CRITICAL] Error reading PCAP file {self.pcap_file}: {e}")
        else:
            self._sniff_live(count)

    def stop(self):
        """
        Stops the sniffing process.
        """
        self.stop_event.set()
        ml_ids_logger.info("[*] ML IDS sniffing stopped.")
