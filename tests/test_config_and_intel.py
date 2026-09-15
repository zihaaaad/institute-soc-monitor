import json
import os
import tempfile
import unittest

from config_loader import ConfigError, load_config, normalize_mac, validate_subnets
from oui_database import UNKNOWN_MAC_VENDOR, load_ieee_registry, lookup_mac_vendor
from threat_intel import (
    COMMANDLINE_RULES, DETECTION_CATALOG, EXPOSURE_CATALOG, PROCESS_DETECTIONS, SEVERITY_ORDER,
    LatencyAnomalyDetector, calculate_endpoint_risk_score, exposure_ids_for_ports,
)


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.tracked = os.path.join(self.tmp.name, "config.json")
        self.local = os.path.join(self.tmp.name, "config.local.json")

    def write(self, path, data):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f)

    def test_mac_normalization(self):
        self.assertEqual(normalize_mac("00-50-56-11-22-33"), "00:50:56:11:22:33")
        self.assertEqual(normalize_mac("005056112233"), "00:50:56:11:22:33")
        self.assertIsNone(normalize_mac("00:50-56:11:22:33"))
        self.assertIsNone(normalize_mac("Static/LAN"))

    def test_precedence_local_file_and_env(self):
        self.write(self.tracked, {"subnets": {"10.1.0.0/24": "Lab"}, "credentials": {"windows_user": "tracked"}})
        self.write(self.local, {"credentials": {"windows_user": "local"}})
        cfg = load_config(self.tracked, self.local, environ={"MONITRO_WINDOWS_PASSWORD": "from-env"})
        self.assertEqual(cfg["credentials"]["windows_user"], "local")
        self.assertEqual(cfg["credentials"]["windows_password"], "from-env")

    def test_secret_in_tracked_config_warns(self):
        self.write(self.tracked, {"subnets": {"10.1.0.0/24": "Lab"}, "credentials": {"windows_password": "oops"}})
        with self.assertLogs("monitro.config", level="WARNING") as logs:
            load_config(self.tracked, self.local, environ={})
        self.assertTrue(any("tracked by git" in line for line in logs.output))

    def test_invalid_json_fails_loudly(self):
        with open(self.tracked, "w") as f:
            f.write("{not json")
        with self.assertRaises(ConfigError):
            load_config(self.tracked, self.local, environ={})

    def test_subnet_guardrails(self):
        with self.assertLogs("monitro.config", level="ERROR"):
            valid = validate_subnets({"10.0.0.0/24": "ok", "8.8.8.0/24": "public", "10.0.0.0/8": "huge", "bogus": "x"}, allow_public=False)
        self.assertEqual(list(valid), ["10.0.0.0/24"])

    def test_all_invalid_subnets_is_an_error(self):
        self.write(self.tracked, {"subnets": {"not-a-subnet": "x"}})
        with self.assertRaises(ConfigError):
            load_config(self.tracked, self.local, environ={})

    def test_whitelist_normalized_and_legacy_key(self):
        self.write(self.tracked, {"subnets": {"10.1.0.0/24": "Lab"}, "asset_whitelist": ["AA-BB-CC-DD-EE-FF", "10.1.0.5"],
                                  "vulnerability_audit": {"check_cleartext_http": False}})
        cfg = load_config(self.tracked, self.local, environ={})
        self.assertEqual(cfg["asset_whitelist"], ["aa:bb:cc:dd:ee:ff"])  # IPs are not identity and are rejected
        self.assertFalse(cfg["vulnerability_audit"]["check_cleartext_protocols"])


class OuiTests(unittest.TestCase):
    def test_registry_takes_precedence_and_fallbacks(self):
        registry = {"00:50:56": "VMware, Inc."}
        self.assertEqual(lookup_mac_vendor("00-50-56-00-00-01", registry), "VMware, Inc.")
        self.assertEqual(lookup_mac_vendor("E0:D5:5E:11:22:33", {}), "GIGA-BYTE TECHNOLOGY CO.,LTD.")
        self.assertEqual(lookup_mac_vendor("Static/LAN", {}), UNKNOWN_MAC_VENDOR)
        self.assertEqual(lookup_mac_vendor(None, {}), UNKNOWN_MAC_VENDOR)
        self.assertEqual(lookup_mac_vendor("da:a1:19:00:00:01", {}), "Randomized / Locally Administered MAC")
        self.assertEqual(lookup_mac_vendor("f4:00:00:00:00:01", {}), "Unregistered Vendor")

    def test_csv_parsing(self):
        with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False, encoding="utf-8") as f:
            f.write('Registry,Assignment,Organization Name,Organization Address\nMA-L,286FB9,"Nokia Shanghai Bell Co., Ltd.",addr\n')
        self.addCleanup(os.remove, f.name)
        self.assertEqual(load_ieee_registry(f.name), {"28:6f:b9": "Nokia Shanghai Bell Co., Ltd."})


class ThreatIntelTests(unittest.TestCase):
    def test_catalog_entries_are_complete(self):
        required = {"severity", "weight", "technique_id", "technique_name", "tactic"}
        for catalog in (EXPOSURE_CATALOG, DETECTION_CATALOG, PROCESS_DETECTIONS):
            for key, info in catalog.items():
                self.assertTrue(required <= set(info), key)
                self.assertIn(info["severity"], SEVERITY_ORDER, key)
        for rule in COMMANDLINE_RULES:
            self.assertTrue(required <= set(rule), rule["rule_id"])

    def test_risk_score_diminishing_and_capped(self):
        self.assertEqual(calculate_endpoint_risk_score([], is_rogue=False), 0.0)
        self.assertEqual(calculate_endpoint_risk_score(["RPC-EXPOSURE"]), 0.0)  # INFO does not add risk
        self.assertEqual(calculate_endpoint_risk_score(["SMBV1-ENABLED"]), 81.0)
        self.assertEqual(calculate_endpoint_risk_score([3.0, 3.0]), 45.0)       # 30 + 15
        many_low = calculate_endpoint_risk_score([3.0] * 10)
        self.assertLess(many_low, calculate_endpoint_risk_score([9.5]))
        self.assertEqual(calculate_endpoint_risk_score(["SMBV1-ENABLED", "mimikatz.exe"], is_rogue=True), 100.0)

    def test_exposures_from_ports(self):
        cfg = {"enabled": True}
        ids = exposure_ids_for_ports([23, 80, 135, 3389, 5900, 3306], smbv1=True, vuln_config=cfg)
        self.assertEqual(set(ids), {"SMBV1-ENABLED", "TELNET-CLEARTEXT", "HTTP-CLEARTEXT", "RDP-EXPOSURE",
                                    "VNC-EXPOSURE", "DATABASE-EXPOSURE", "RPC-EXPOSURE"})
        self.assertEqual(exposure_ids_for_ports([23], smbv1=True, vuln_config={"enabled": False}), [])

    def test_latency_detector_per_host_baseline(self):
        detector = LatencyAnomalyDetector(z_threshold=3.0, min_delta_ms=15)
        for value in [2.0, 2.2, 1.9, 2.1] * 5:
            self.assertFalse(detector.update(value)[0])
        self.assertFalse(detector.update(4.0)[0])   # large z, but only 2ms: jitter, not an incident
        self.assertTrue(detector.update(250.0)[0])


if __name__ == "__main__":
    unittest.main()
