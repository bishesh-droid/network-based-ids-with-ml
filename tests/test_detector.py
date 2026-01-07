import unittest
from unittest.mock import patch, MagicMock, mock_open
import numpy as np
from scapy.all import IP, TCP, UDP, ICMP, Raw

from ml_ids.detector import MLIntrusionDetector
from ml_ids.model import extract_features, load_model, _train_dummy_model, MODEL_PATH

class TestModel(unittest.TestCase):

    def setUp(self):
        # Mock the logger
        patch('ml_ids.model.ml_ids_logger').start()
        self.addCleanup(patch.stopall)

    def _create_mock_packet(self, src_ip, dst_ip, proto_type, payload_len=0, tcp_flags=""):
        """
        Helper to create a mock Scapy packet.
        """
        packet = IP(src=src_ip, dst=dst_ip)
        if proto_type == "TCP":
            packet /= TCP(flags=tcp_flags)
        elif proto_type == "UDP":
            packet /= UDP()
        elif proto_type == "ICMP":
            packet /= ICMP()
        
        if payload_len > 0:
            packet /= Raw(load=b'A' * payload_len)
        
        # Mock len() for the packet object
        packet.__len__ = MagicMock(return_value=len(packet))
        return packet

    def test_extract_features_tcp(self):
        packet = self._create_mock_packet("192.168.1.1", "8.8.8.8", "TCP", payload_len=50, tcp_flags="SA")
        features = extract_features(packet)
        # Expected features: [len, ttl, is_tcp, is_udp, is_icmp, has_raw, tcp_flags_sum, src_port, dst_port, ip_flags, ip_frag]
        self.assertEqual(features[0][0], len(packet))
        self.assertEqual(features[0][1], 64)
        self.assertEqual(features[0][2], 1)
        self.assertEqual(features[0][6], 18) # S=2, A=16 -> 18
        self.assertEqual(features[0][9], 0)
        self.assertEqual(features[0][10], 0)

    def test_extract_features_udp(self):
        packet = self._create_mock_packet("192.168.1.2", "4.4.4.4", "UDP", payload_len=30)
        features = extract_features(packet)
        self.assertEqual(features[0][0], len(packet))
        self.assertEqual(features[0][1], 64)
        self.assertEqual(features[0][3], 1)
        self.assertEqual(features[0][6], 0) # No TCP flags for UDP
        self.assertEqual(features[0][9], 0)
        self.assertEqual(features[0][10], 0)

    @patch('pickle.dump')
    @patch('os.path.exists', return_value=False)
    def test_load_model_trains_and_saves_if_not_found(self, mock_exists, mock_dump):
        model = load_model()
        self.assertIsNotNone(model)
        mock_dump.assert_called_once()

    @patch('pickle.load')
    @patch('builtins.open', new_callable=mock_open)
    @patch('os.path.exists', return_value=True)
    def test_load_model_loads_if_found(self, mock_exists, mock_open, mock_load):
        mock_load.return_value = MagicMock()
        model = load_model()
        self.assertIsNotNone(model)
        mock_open.assert_called_with(MODEL_PATH, 'rb')
        mock_load.assert_called_once()

class TestMLIntrusionDetector(unittest.TestCase):

    def setUp(self):
        self.interface = "lo"
        # Mock the logger
        self.mock_logger = MagicMock()
        patch('ml_ids.detector.ml_ids_logger', self.mock_logger).start()
        patch('ml_ids.logger.ml_ids_logger', self.mock_logger).start()
        self.addCleanup(patch.stopall)

        # Mock the model loading to return a simple mock model
        self.mock_model = MagicMock()
        self.mock_model.predict.return_value = [0] # Default to normal
        patch('ml_ids.detector.load_model', return_value=self.mock_model).start()

        self.detector = MLIntrusionDetector(interface=self.interface)

    def _create_mock_packet(self, src_ip, dst_ip, proto_type, payload_len=0, tcp_flags=""):
        """
        Helper to create a mock Scapy packet.
        """
        packet = IP(src=src_ip, dst=dst_ip)
        if proto_type == "TCP":
            packet /= TCP(flags=tcp_flags)
        elif proto_type == "UDP":
            packet /= UDP()
        elif proto_type == "ICMP":
            packet /= ICMP()
        
        if payload_len > 0:
            packet /= Raw(load=b'A' * payload_len)
        
        # Mock len() for the packet object
        packet.__len__ = MagicMock(return_value=len(packet))
        return packet

    def test_process_packet_normal(self):
        self.mock_logger.reset_mock()
        packet = self._create_mock_packet("192.168.1.1", "8.8.8.8", "TCP", payload_len=50)
        self.detector._process_packet(packet)
        self.mock_model.predict.assert_called_once()
        self.mock_logger.info.assert_called_once()
        self.assertIn("Normal traffic", str(self.mock_logger.info.call_args_list))

    def test_process_packet_anomalous(self):
        self.mock_logger.reset_mock()
        self.mock_model.predict.return_value = [1] # Simulate anomalous prediction
        packet = self._create_mock_packet("192.168.1.10", "1.2.3.4", "TCP", payload_len=100, tcp_flags="S")
        self.detector._process_packet(packet)
        self.mock_model.predict.assert_called_once()
        self.mock_logger.warning.assert_called()
        self.assertIn("Anomalous traffic detected!", str(self.mock_logger.warning.call_args_list))

    @patch('scapy.all.sniff', side_effect=PermissionError("Permission denied"))
    def test_start_sniffing_live_no_permission(self, mock_sniff):
        self.mock_logger.reset_mock()
        self.detector.start_sniffing()
        self.mock_logger.critical.assert_called()
        self.assertIn("permission", str(self.mock_logger.critical.call_args_list).lower())

    @patch('scapy.all.sniff', side_effect=FileNotFoundError("File not found"))
    def test_start_sniffing_pcap_not_found(self, mock_sniff):
        self.mock_logger.reset_mock()
        detector = MLIntrusionDetector(pcap_file="non_existent.pcap")
        detector.start_sniffing()
        self.mock_logger.critical.assert_called()
        self.assertIn("no such file or directory", str(self.mock_logger.critical.call_args_list).lower())

    @patch('scapy.all.sniff', side_effect=Exception("Sniffing error"))
    def test_start_sniffing_error(self, mock_sniff):
        self.mock_logger.reset_mock()
        self.detector.start_sniffing()
        self.mock_logger.critical.assert_called()
        self.assertIn("CRITICAL", str(self.mock_logger.critical.call_args_list))

if __name__ == '__main__':
    unittest.main()
