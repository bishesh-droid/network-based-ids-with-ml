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
    def __init__(self, interface=NETWORK_INTERFACE, pcap_file=None):
        """
        Initializes the MLIntrusionDetector.

        Args:
            interface (str): The network interface to sniff on.
            pcap_file (str, optional): Path to a PCAP file to read packets from instead of live sniffing.
        """
        self.interface = interface
        self.pcap_file = pcap_file
        self.model = load_model()
        self.stop_event = threading.Event() # For graceful shutdown

        if self.pcap_file:
            ml_ids_logger.info(f"[*] Initialized ML IDS to read from PCAP file: {self.pcap_file}")
        else:
            ml_ids_logger.info(f"[*] Initialized ML IDS on interface: {self.interface}")

    def _process_packet(self, packet):
        """
        Processes a single captured packet.
        Extracts features and uses the ML model to predict if it's anomalous.
        """
        if IP in packet:
            try:
                features = extract_features(packet)
                prediction = self.model.predict(features)[0]

                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                protocol = packet[IP].proto

                if TCP in packet:
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    protocol_name = "TCP"
                elif UDP in packet:
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                    protocol_name = "UDP"
                elif ICMP in packet:
                    src_port = "N/A"
                    dst_port = "N/A"
                    protocol_name = "ICMP"
                else:
                    src_port = "N/A"
                    dst_port = "N/A"
                    protocol_name = str(protocol)

                if prediction == 1: # Assuming 1 means anomalous/attack
                    ml_ids_logger.warning(f"[ALERT] Anomalous traffic detected!")
                    ml_ids_logger.warning(f"        Source: {src_ip}:{src_port} -> Destination: {dst_ip}:{dst_port} (Protocol: {protocol_name})")
                    ml_ids_logger.warning(f"        Features: {features}")
                else:
                    ml_ids_logger.info(f"[NORMAL] Normal traffic: {src_ip}:{src_port} -> {dst_ip}:{dst_port} (Protocol: {protocol_name})")

            except Exception as e:
                ml_ids_logger.error(f"[ERROR] Error processing packet: {e}")
        # else:
        #     ml_ids_logger.debug("Non-IP packet received.")

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
                return
        else:
            ml_ids_logger.info(f"[*] Starting live packet sniffing on {self.interface}...")
            try:
                sniff(iface=self.interface, prn=self._process_packet, store=0, count=count, stop_filter=lambda p: self.stop_event.is_set())
            except Exception as e:
                ml_ids_logger.critical(f"[CRITICAL] Error during live sniffing on {self.interface}: {e}")
                ml_ids_logger.critical("        Ensure you have sufficient permissions (e.g., run as root/administrator) and the interface name is correct.")
                return

    def stop(self):
        """
        Stops the sniffing process.
        """
        self.stop_event.set()
        ml_ids_logger.info("[*] ML IDS sniffing stopped.")
