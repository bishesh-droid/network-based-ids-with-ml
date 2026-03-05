import unittest
from unittest.mock import patch, MagicMock, mock_open
import numpy as np
from scapy.all import IP, TCP, UDP, ICMP, Raw

from ml_ids.detector import MLIntrusionDetector, PacketStats
from ml_ids.model import extract_features, load_model, _train_dummy_model, classify_threat, ThreatType
from ml_ids.config import MODEL_PATH


class TestModel(unittest.TestCase):

    def setUp(self):
        patch("ml_ids.model.ml_ids_logger").start()
        self.addCleanup(patch.stopall)

    def _create_packet(self, src_ip, dst_ip, proto_type, payload_len=0, tcp_flags=""):
        packet = IP(src=src_ip, dst=dst_ip)
        if proto_type == "TCP":
            packet /= TCP(flags=tcp_flags)
        elif proto_type == "UDP":
            packet /= UDP()
        elif proto_type == "ICMP":
            packet /= ICMP()
        if payload_len > 0:
            packet /= Raw(load=b"A" * payload_len)
        return packet

    # --- extract_features ---------------------------------------------------

    def test_extract_features_tcp(self):
        packet = self._create_packet("192.168.1.1", "8.8.8.8", "TCP",
                                     payload_len=50, tcp_flags="SA")
        features = extract_features(packet)
        # 13 features total
        self.assertEqual(features.shape, (1, 13))
        self.assertEqual(features[0][1], 64)   # default TTL
        self.assertEqual(features[0][2], 1)    # is_tcp
        self.assertEqual(features[0][3], 0)    # is_udp
        self.assertEqual(features[0][4], 0)    # is_icmp
        self.assertEqual(features[0][6], 18)   # SYN(2) + ACK(16) = 18
        self.assertEqual(features[0][9],  0)   # ip_flags (DF not set in test pkt)
        self.assertEqual(features[0][10], 0)   # ip_frag
        self.assertEqual(features[0][11], 5)   # ip_ihl (no options)
        self.assertEqual(features[0][12], 0)   # ip_tos

    def test_extract_features_udp(self):
        packet = self._create_packet("192.168.1.2", "4.4.4.4", "UDP",
                                     payload_len=30)
        features = extract_features(packet)
        self.assertEqual(features.shape, (1, 13))
        self.assertEqual(features[0][1], 64)
        self.assertEqual(features[0][3], 1)    # is_udp
        self.assertEqual(features[0][6], 0)    # no TCP flags

    def test_extract_features_icmp(self):
        packet = self._create_packet("10.0.0.1", "10.0.0.2", "ICMP")
        features = extract_features(packet)
        self.assertEqual(features[0][4], 1)    # is_icmp
        self.assertEqual(features[0][2], 0)    # not TCP
        self.assertEqual(features[0][3], 0)    # not UDP

    # --- load_model ---------------------------------------------------------

    @patch("pickle.dump")
    @patch("os.path.exists", return_value=False)
    def test_load_model_trains_and_saves_if_not_found(self, _exists, mock_dump):
        model = load_model()
        self.assertIsNotNone(model)
        mock_dump.assert_called_once()

    @patch("pickle.load")
    @patch("builtins.open", new_callable=mock_open)
    @patch("os.path.exists", return_value=True)
    def test_load_model_loads_if_found(self, _exists, _open, mock_load):
        from ml_ids.config import MODEL_VERSION
        mock_load.return_value = {"version": MODEL_VERSION, "model": MagicMock()}
        model = load_model()
        self.assertIsNotNone(model)
        mock_load.assert_called_once()

    @patch("pickle.dump")
    @patch("pickle.load")
    @patch("builtins.open", new_callable=mock_open)
    @patch("os.path.exists", return_value=True)
    def test_load_model_retrains_on_version_mismatch(self, _exists, _open,
                                                      mock_load, mock_dump):
        mock_load.return_value = {"version": "0.0", "model": MagicMock()}
        model = load_model()
        self.assertIsNotNone(model)
        # Model was retrained and re-saved because the version did not match
        mock_dump.assert_called_once()

    # --- classify_threat ----------------------------------------------------

    def test_classify_threat_normal(self):
        features = np.array([[60, 64, 1, 0, 0, 0, 2, 1234, 80, 0, 0, 5, 0]])
        self.assertEqual(classify_threat(features, 0), ThreatType.NORMAL)

    def test_classify_threat_syn_flood(self):
        # Pure SYN (flags=2) with large packet
        features = np.array([[150, 64, 1, 0, 0, 1, 2, 1234, 80, 0, 0, 5, 0]])
        result = classify_threat(features, 1)
        self.assertEqual(result, ThreatType.SYN_FLOOD)

    def test_classify_threat_fragmentation(self):
        features = np.array([[400, 64, 1, 0, 0, 1, 2, 1234, 80, 0, 1, 5, 0]])
        result = classify_threat(features, 1)
        self.assertEqual(result, ThreatType.FRAGMENTATION_ATTACK)

    def test_classify_threat_suspicious_port(self):
        features = np.array([[60, 64, 1, 0, 0, 0, 2, 1234, 445, 0, 0, 5, 0]])
        result = classify_threat(features, 1)
        self.assertEqual(result, ThreatType.SUSPICIOUS_PORT)

    def test_classify_threat_anomalous_payload(self):
        features = np.array([[500, 64, 1, 0, 0, 1, 16, 1234, 8080, 0, 0, 5, 0]])
        result = classify_threat(features, 1)
        self.assertEqual(result, ThreatType.ANOMALOUS_PAYLOAD)


class TestMLIntrusionDetector(unittest.TestCase):

    def setUp(self):
        self.mock_logger = MagicMock()
        patch("ml_ids.detector.ml_ids_logger", self.mock_logger).start()
        patch("ml_ids.logger.ml_ids_logger",   self.mock_logger).start()
        self.addCleanup(patch.stopall)

        self.mock_model = MagicMock()
        self.mock_model.predict.return_value = [0]  # Default: normal
        patch("ml_ids.detector.load_model", return_value=self.mock_model).start()

        self.detector = MLIntrusionDetector(interface="lo")

    def _create_packet(self, src_ip, dst_ip, proto_type, payload_len=0, tcp_flags=""):
        packet = IP(src=src_ip, dst=dst_ip)
        if proto_type == "TCP":
            packet /= TCP(flags=tcp_flags)
        elif proto_type == "UDP":
            packet /= UDP()
        elif proto_type == "ICMP":
            packet /= ICMP()
        if payload_len > 0:
            packet /= Raw(load=b"A" * payload_len)
        return packet

    # --- _process_packet ----------------------------------------------------

    def test_process_packet_normal(self):
        self.mock_logger.reset_mock()
        packet = self._create_packet("192.168.1.1", "8.8.8.8", "TCP", payload_len=50)
        self.detector._process_packet(packet)
        self.mock_model.predict.assert_called_once()
        self.mock_logger.info.assert_called()
        self.assertIn("NORMAL", str(self.mock_logger.info.call_args_list))

    def test_process_packet_anomalous(self):
        self.mock_logger.reset_mock()
        self.mock_model.predict.return_value = [1]
        packet = self._create_packet("192.168.1.10", "1.2.3.4", "TCP",
                                     payload_len=100, tcp_flags="S")
        self.detector._process_packet(packet)
        self.mock_model.predict.assert_called_once()
        self.mock_logger.warning.assert_called()

    def test_process_packet_updates_stats(self):
        # Two normal, one anomalous
        p_normal    = self._create_packet("10.0.0.1", "10.0.0.2", "TCP")
        p_anomalous = self._create_packet("10.0.0.3", "10.0.0.4", "UDP")

        self.detector._process_packet(p_normal)
        self.mock_model.predict.return_value = [1]
        self.detector._process_packet(p_anomalous)

        stats = self.detector.get_stats()
        self.assertEqual(stats.total,     2)
        self.assertEqual(stats.anomalous, 1)
        self.assertAlmostEqual(stats.anomaly_rate, 50.0)

    def test_process_non_ip_packet_skipped(self):
        from scapy.all import Ether
        self.mock_logger.reset_mock()
        self.detector._process_packet(Ether())
        self.mock_model.predict.assert_not_called()

    # --- stats --------------------------------------------------------------

    def test_get_stats_returns_packet_stats(self):
        stats = self.detector.get_stats()
        self.assertIsInstance(stats, PacketStats)

    def test_stats_anomaly_rate_zero_when_no_packets(self):
        self.assertEqual(self.detector.stats.anomaly_rate, 0.0)

    # --- start_sniffing errors ----------------------------------------------

    @patch("scapy.all.sniff", side_effect=PermissionError("Permission denied"))
    def test_start_sniffing_live_no_permission(self, _mock_sniff):
        self.mock_logger.reset_mock()
        self.detector.start_sniffing()
        self.mock_logger.critical.assert_called()
        self.assertIn("permission", str(self.mock_logger.critical.call_args_list).lower())

    @patch("scapy.all.sniff", side_effect=FileNotFoundError("File not found"))
    def test_start_sniffing_pcap_not_found(self, _mock_sniff):
        self.mock_logger.reset_mock()
        detector = MLIntrusionDetector(pcap_file="non_existent.pcap")
        detector.start_sniffing()
        self.mock_logger.critical.assert_called()
        # The log message contains the PCAP filename and the error string
        logged = str(self.mock_logger.critical.call_args_list).lower()
        self.assertIn("error reading pcap file", logged)

    @patch("scapy.all.sniff", side_effect=Exception("Sniffing error"))
    def test_start_sniffing_generic_error(self, _mock_sniff):
        self.mock_logger.reset_mock()
        self.detector.start_sniffing()
        self.mock_logger.critical.assert_called()


if __name__ == "__main__":
    unittest.main()
