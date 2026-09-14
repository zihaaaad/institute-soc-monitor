import unittest
import os
import sys

# Add src to path
SRC_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from config_loader import load_config, normalize_mac
from oui_database import lookup_mac_vendor, UNKNOWN_MAC_VENDOR
from threat_intel import MITRE_TECHNIQUES, calculate_endpoint_risk_score, LatencyAnomalyDetector
from agentless_monitor_win import make_smbv1_negotiate_packet

class TestMonitroSuite(unittest.TestCase):

    def test_mac_normalization(self):
        self.assertEqual(normalize_mac("00-50-56-11-22-33"), "00:50:56:11:22:33")
        self.assertEqual(normalize_mac("00:50:56:11:22:33"), "00:50:56:11:22:33")
        self.assertEqual(normalize_mac("005056112233"), "00:50:56:11:22:33")
        self.assertIsNone(normalize_mac("invalid_mac"))
        self.assertIsNone(normalize_mac("Static/LAN"))

    def test_oui_vendor_lookup(self):
        # Case insensitivity & formatting
        self.assertEqual(lookup_mac_vendor("00:50:56:00:00:01"), "VMware, Inc.")
        self.assertEqual(lookup_mac_vendor("00-50-56-00-00-01"), "VMware, Inc.")
        self.assertEqual(lookup_mac_vendor("E4:54:E8:11:22:33"), "Dell Inc.")
        
        # Unknown / static / unresolvable fallbacks
        self.assertEqual(lookup_mac_vendor("Static/LAN"), UNKNOWN_MAC_VENDOR)
        self.assertEqual(lookup_mac_vendor(None), UNKNOWN_MAC_VENDOR)
        self.assertEqual(lookup_mac_vendor(""), UNKNOWN_MAC_VENDOR)
        
        # Locally administered / random MACs
        self.assertEqual(lookup_mac_vendor("02:00:00:00:00:00"), "Randomized / Locally Administered MAC")

    def test_smbv1_packet_integrity(self):
        packet = make_smbv1_negotiate_packet()
        # NetBIOS header (4 bytes)
        self.assertEqual(packet[0], 0x00) # Session message
        payload_len = int.from_bytes(packet[1:4], "big")
        # Ensure NetBIOS length equals actual payload bytes
        self.assertEqual(payload_len, len(packet) - 4)
        # Check SMBv1 signature
        self.assertEqual(packet[4:8], b"\xffSMB")
        self.assertEqual(packet[8], 0x72) # SMB_COM_NEGOTIATE

    def test_risk_score_calculation(self):
        # Zero vulnerabilities / benign host
        score_clean = calculate_endpoint_risk_score([], is_rogue=False)
        self.assertEqual(score_clean, 0.0)

        # High-risk SMBv1 vulnerability
        score_smb = calculate_endpoint_risk_score(["SMBV1-ENABLED"], is_rogue=False)
        self.assertGreater(score_smb, 20.0)

        # Rogue host penalty
        score_rogue = calculate_endpoint_risk_score([], is_rogue=True)
        self.assertGreaterEqual(score_rogue, 30.0)

        # Capped at 100.0
        score_max = calculate_endpoint_risk_score(["SMBV1-ENABLED", "TELNET-CLEARTEXT", "mimikatz.exe", "psexec.exe"], is_rogue=True)
        self.assertEqual(score_max, 100.0)


    def test_anomaly_detector(self):
        detector = LatencyAnomalyDetector(z_threshold=3.0)
        # Feed nominal latencies (around 2.0ms)
        for _ in range(20):
            is_anomaly, z = detector.update(2.0)
            self.assertFalse(is_anomaly)
        
        # Feed huge latency spike (500ms)
        is_anomaly, z = detector.update(500.0)
        self.assertTrue(is_anomaly)
        self.assertGreater(z, 3.0)

    def test_mitre_techniques_mapping(self):
        self.assertIn("BRUTE-FORCE", MITRE_TECHNIQUES)
        self.assertEqual(MITRE_TECHNIQUES["BRUTE-FORCE"]["technique_id"], "T1110.001")
        self.assertIn("mimikatz.exe", MITRE_TECHNIQUES)
        self.assertEqual(MITRE_TECHNIQUES["mimikatz.exe"]["technique_id"], "T1003.001")

if __name__ == "__main__":
    unittest.main()
