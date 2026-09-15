import re
import tempfile
import unittest

from alerting import AlertDispatcher
from wmi_audit import FailedLogonEvent, WmiAuditor, analyze_failed_logons, analyze_processes


def events(n, start=100, source="10.13.118.44", users=None):
    users = users or ["student"]
    return [FailedLogonEvent(record=start + i, target_user=users[i % len(users)], source_ip=source, logon_type="3")
            for i in range(n)]


class FailedLogonTests(unittest.TestCase):
    def test_events_are_never_double_counted(self):
        first = analyze_failed_logons(events(12), last_record=None, brute_force_threshold=10, spray_account_threshold=5)
        self.assertEqual(first.new_events, 12)
        self.assertEqual([d["id"] for d in first.detections], ["BRUTE-FORCE"])
        # Same events returned again by the lookback window: nothing new
        again = analyze_failed_logons(events(12), last_record=first.max_record, brute_force_threshold=10, spray_account_threshold=5)
        self.assertEqual(again.new_events, 0)
        self.assertEqual(again.detections, [])
        self.assertEqual(again.max_record, first.max_record)

    def test_password_spray(self):
        spray = events(6, users=["alice", "bob", "carol", "dave", "erin", "frank"])
        result = analyze_failed_logons(spray, None, brute_force_threshold=50, spray_account_threshold=5)
        self.assertEqual([d["id"] for d in result.detections], ["PASSWORD-SPRAY"])
        self.assertEqual(result.detections[0]["technique_id"], "T1110.003")

    def test_invalid_source_is_normalised(self):
        result = analyze_failed_logons(events(1, source="-"), None, 10, 5)
        self.assertEqual(result.top_sources, [("local/unknown", 1)])


class ProcessTests(unittest.TestCase):
    def test_blacklist_and_commandline_rules(self):
        procs = [
            {"name": "explorer.exe", "pid": 1, "cmdline": "C:\\Windows\\explorer.exe"},
            {"name": "powershell.exe", "pid": 2, "cmdline": "powershell.exe -NoP -W Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA"},
            {"name": "MIMIKATZ.EXE", "pid": 3, "cmdline": ""},
            {"name": "rundll32.exe", "pid": 4, "cmdline": "rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump 624 lsass.dmp full"},
            {"name": "cmd.exe", "pid": 5, "cmdline": "cmd.exe /c whoami /priv"},
        ]
        detections, names = analyze_processes(procs, ["mimikatz.exe", "custom-tool.exe"], [re.compile(r"whoami\s+/priv")])
        ids = {d["id"] for d in detections}
        self.assertEqual(names, ["mimikatz.exe"])
        self.assertTrue({"PROC:mimikatz.exe", "PS-ENCODED", "PS-HIDDEN-WINDOW", "LSASS-MINIDUMP", "CUSTOM-COMMANDLINE"} <= ids)
        self.assertNotIn("powershell.exe", names)  # a running shell alone is not a detection

    def test_benign_powershell_is_quiet(self):
        detections, _ = analyze_processes([{"name": "powershell.exe", "pid": 9, "cmdline": "powershell.exe -File C:\\scripts\\backup.ps1"}], [], [])
        self.assertEqual(detections, [])


class AuditorEligibilityTests(unittest.TestCase):
    def make(self, **wmi):
        cfg = {"credentials": {"windows_user": "svc", "windows_password": "pw"}, "wmi_audit": {"enabled": True, **wmi},
               "suspicious_processes": [], "local_ip": "10.0.0.9", "settings": {"scan_interval_seconds": 60}}
        auditor = WmiAuditor(cfg, session_factory=lambda *a: (_ for _ in ()).throw(AssertionError("no connection in tests")))
        self.addCleanup(auditor.shutdown)
        return auditor

    def test_credentials_never_sent_to_unapproved_hosts(self):
        auditor = self.make()
        base = {"ip": "10.0.0.5", "open_ports": [135, 445]}
        self.assertTrue(auditor.eligibility({**base, "asset_status": "authorized"})[0])
        for status in ("rogue", "unverified", "unmanaged"):
            self.assertFalse(auditor.eligibility({**base, "asset_status": status})[0], status)
        self.assertFalse(auditor.eligibility({**base, "ip": "10.0.0.9", "asset_status": "authorized"})[0])
        self.assertFalse(auditor.eligibility({"ip": "10.0.0.6", "open_ports": [80], "asset_status": "authorized"})[0])

    def test_unverified_opt_in_still_excludes_rogue(self):
        auditor = self.make(audit_unverified_hosts=True)
        base = {"ip": "10.0.0.5", "open_ports": [135]}
        self.assertTrue(auditor.eligibility({**base, "asset_status": "unverified"})[0])
        self.assertFalse(auditor.eligibility({**base, "asset_status": "rogue"})[0])


class AlertTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.now = [1000.0]
        self.sent = []
        self.dispatcher = AlertDispatcher(
            {"enabled": False, "alert_cooldown_seconds": 300, "discord_webhook_url": "https://discord.example/hook"},
            log_dir=self.tmp.name, sender=lambda url, payload: self.sent.append((url, payload)), clock=lambda: self.now[0])
        self.addCleanup(self.dispatcher.close)  # runs before tmp cleanup (LIFO)

    def test_cooldown_deduplicates(self):
        with self.assertLogs("monitro.alerts", level="WARNING"):
            self.assertTrue(self.dispatcher.dispatch("t", "HIGH", "10.0.0.1", "rogue", "m"))
            self.assertFalse(self.dispatcher.dispatch("t", "HIGH", "10.0.0.1", "rogue", "m"))
            self.assertTrue(self.dispatcher.dispatch("t", "HIGH", "10.0.0.2", "rogue", "m"))
            self.now[0] += 301
            self.assertTrue(self.dispatcher.dispatch("t", "HIGH", "10.0.0.1", "rogue", "m"))
        with open(f"{self.tmp.name}/alerts.jsonl", encoding="utf-8") as f:
            self.assertEqual(len(f.readlines()), 3)

    def test_discord_payload_blocks_mentions_and_hides_evidence(self):
        event = {"severity": "HIGH", "title": "@everyone pwned", "target_ip": "10.0.0.1", "timestamp": "now",
                 "message": "host <@123>", "evidence": "password=hunter2"}
        payload = self.dispatcher.build_discord_payload(event)
        self.assertEqual(payload["allowed_mentions"], {"parse": []})
        self.assertNotIn("hunter2", str(payload))

    def test_plain_http_webhook_rejected(self):
        with self.assertLogs("monitro.alerts", level="ERROR"):
            d = AlertDispatcher({"discord_webhook_url": "http://insecure/hook"}, log_dir="")
        self.assertEqual(d.config["discord_webhook_url"], "")


if __name__ == "__main__":
    unittest.main()
