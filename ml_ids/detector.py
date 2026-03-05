from collections import defaultdict
from dataclasses import dataclass, field

from scapy.all import sniff, IP, TCP, UDP, ICMP
import numpy as np

from .logger import ml_ids_logger
from .config import NETWORK_INTERFACE
from .model import load_model, extract_features, classify_threat, ThreatType


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------

@dataclass
class PacketStats:
    """Tracks aggregate statistics for the current sniffing session."""
    total: int = 0
    anomalous: int = 0
    by_protocol: dict = field(default_factory=lambda: defaultdict(int))
    by_threat: dict = field(default_factory=lambda: defaultdict(int))

    @property
    def anomaly_rate(self) -> float:
        """Percentage of packets classified as anomalous."""
        return (self.anomalous / self.total * 100) if self.total else 0.0

    def summary(self) -> str:
        proto_str  = ", ".join(f"{k}: {v}" for k, v in sorted(self.by_protocol.items()))
        threat_str = ", ".join(f"{k}: {v}" for k, v in sorted(self.by_threat.items()) if k != "Normal")
        lines = [
            f"  Total packets  : {self.total}",
            f"  Anomalous      : {self.anomalous} ({self.anomaly_rate:.1f}%)",
            f"  By protocol    : {proto_str or 'N/A'}",
        ]
        if threat_str:
            lines.append(f"  Threat types   : {threat_str}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

class MLIntrusionDetector:
    """
    Network Intrusion Detection System (NIDS) driven by a machine-learning
    classifier.  Supports both live packet capture and offline PCAP analysis.
    """

    def __init__(self, interface: str = NETWORK_INTERFACE,
                 pcap_file: str = None, model_path: str = None):
        """
        Args:
            interface:   Network interface for live sniffing.
            pcap_file:   Path to a PCAP file (overrides live sniffing).
            model_path:  Path to a pickled ML model.  None = use default.
        """
        self.interface  = interface
        self.pcap_file  = pcap_file
        self.model      = load_model(model_path) if model_path else load_model()
        self.stats      = PacketStats()
        self._running   = False

        if self.pcap_file:
            ml_ids_logger.info(f"[*] Initialized ML IDS — reading from PCAP: {self.pcap_file}")
        else:
            ml_ids_logger.info(f"[*] Initialized ML IDS — interface: {self.interface}")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_protocol_name(self, packet) -> str:
        if TCP in packet:
            return "TCP"
        elif UDP in packet:
            return "UDP"
        elif ICMP in packet:
            return "ICMP"
        return str(packet[IP].proto)

    def _log_packet_info(self, prediction: int, src_ip: str, dst_ip: str,
                         protocol: str, src_port, dst_port,
                         features: np.ndarray, threat: ThreatType) -> None:
        status  = "ANOMALOUS" if prediction == 1 else "NORMAL"
        message = (
            f"[{status}] {threat.value}\n"
            f"        {src_ip}:{src_port} -> {dst_ip}:{dst_port}  ({protocol})\n"
            f"        Features: {features[0].tolist()}"
        )
        if prediction == 1:
            ml_ids_logger.warning(message)
        else:
            ml_ids_logger.info(message)

    # ------------------------------------------------------------------
    # Packet processing
    # ------------------------------------------------------------------

    def _process_packet(self, packet) -> None:
        """Extracts features, classifies the packet, and logs the result."""
        if IP not in packet:
            ml_ids_logger.debug("Non-IP packet received, skipping.")
            return

        try:
            features   = extract_features(packet)
            prediction = self.model.predict(features)[0]
            threat     = classify_threat(features, prediction)

            src_ip   = packet[IP].src
            dst_ip   = packet[IP].dst
            protocol = self._get_protocol_name(packet)
            src_port = packet.sport if packet.haslayer(TCP) or packet.haslayer(UDP) else "N/A"
            dst_port = packet.dport if packet.haslayer(TCP) or packet.haslayer(UDP) else "N/A"

            # Update statistics
            self.stats.total += 1
            if prediction == 1:
                self.stats.anomalous += 1
            self.stats.by_protocol[protocol] += 1
            self.stats.by_threat[threat.value] += 1

            self._log_packet_info(prediction, src_ip, dst_ip, protocol,
                                  src_port, dst_port, features, threat)

        except Exception as e:
            ml_ids_logger.error(f"[ERROR] Error processing packet: {e}")

    # ------------------------------------------------------------------
    # Sniffing
    # ------------------------------------------------------------------

    def _sniff_live(self, count: int) -> None:
        ml_ids_logger.info(f"[*] Starting live sniffing on {self.interface}...")
        self._running = True
        try:
            sniff(
                iface=self.interface,
                prn=self._process_packet,
                store=0,
                count=count,
                stop_filter=lambda _p: not self._running,
            )
        except Exception as e:
            ml_ids_logger.critical(
                f"[CRITICAL] Error during live sniffing on {self.interface}: {e}\n"
                "        Ensure you have sufficient permissions (e.g. run as root) "
                "and the interface name is correct."
            )

    def start_sniffing(self, count: int = 0) -> None:
        """
        Start sniffing.  Reads from a PCAP file if one was provided at
        construction time, otherwise captures live traffic.

        Args:
            count: Max packets to process.  0 = unlimited.
        """
        if self.pcap_file:
            ml_ids_logger.info(f"[*] Reading packets from PCAP: {self.pcap_file}...")
            try:
                sniff(offline=self.pcap_file, prn=self._process_packet,
                      store=0, count=count)
            except Exception as e:
                ml_ids_logger.critical(
                    f"[CRITICAL] Error reading PCAP file {self.pcap_file}: {e}"
                )
        else:
            self._sniff_live(count)

        self._log_session_summary()

    def stop(self) -> None:
        """Signal the live sniffing loop to stop gracefully."""
        self._running = False
        ml_ids_logger.info("[*] ML IDS sniffing stopped.")

    def get_stats(self) -> PacketStats:
        """Returns a copy of the current session statistics."""
        return self.stats

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    def _log_session_summary(self) -> None:
        if self.stats.total == 0:
            return
        ml_ids_logger.info(
            "[*] Session summary:\n" + self.stats.summary()
        )
