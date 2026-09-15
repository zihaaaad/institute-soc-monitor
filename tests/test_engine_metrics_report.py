import unittest

from prometheus_client import CollectorRegistry, generate_latest

from engine import SweepEngine, build_host_views, classify_asset, find_duplicate_macs, summarize
from generate_report import STATUS_NO_DATA, STATUS_OK, STATUS_STALE, collect_report_data, render_html, render_markdown
from metrics_collector import SocCollector
from scanner import ProbeResult
from wmi_audit import AuditResult


class FakeNetwork:
    def __init__(self):
        self.live = {}          # ip -> open ports
        self.arp = {}           # ip -> mac
        self.probed = []

    def prober(self, ip, ports, timeout, stop_on_first=False):
        self.probed.append(ip)
        result = ProbeResult(ip=ip)
        open_ports = [p for p in ports if p in self.live.get(ip, [])]
        if open_ports:
            result.responded, result.rtt_ms = True, 1.5
            result.open_ports = open_ports[:1] if stop_on_first else open_ports
        return result


class StaticResolver:
    def resolve(self, ip):
        return f"host-{ip.split('.')[-1]}", "dns"


class FakeAuditor:
    def __init__(self, results=None, totals=None):
        self._results = results or {}
        self._totals = totals or {}

    def results(self):
        return self._results

    def failed_logon_totals(self):
        return self._totals


def make_engine(net, whitelist=(), subnets=None, local_ip="192.168.50.10", clock=None):
    config = {
        "subnets": subnets or {"10.0.0.0/29": "Lab A"},
        "asset_whitelist": list(whitelist),
        "local_ip": local_ip,
        "vulnerability_audit": {"enabled": True},
        "settings": {"probe_timeout_seconds": 0.05, "probe_workers": 4, "scan_interval_seconds": 60,
                     "service_scan_interval_seconds": 900},
    }
    kwargs = {"clock": clock} if clock else {}
    return SweepEngine(config, prober=net.prober, arp_reader=lambda: dict(net.arp), mac_resolver=lambda ip: None,
                       smb_checker=lambda ip: True, resolver=StaticResolver(), **kwargs)


class EngineTests(unittest.TestCase):
    def test_asset_classification(self):
        wl = {"aa:aa:aa:00:00:01"}
        self.assertEqual(classify_asset("aa:aa:aa:00:00:01", wl), "authorized")
        self.assertEqual(classify_asset("aa:aa:aa:00:00:02", wl), "rogue")
        self.assertEqual(classify_asset(None, wl), "unverified")
        self.assertEqual(classify_asset("aa:aa:aa:00:00:02", set()), "unmanaged")

    def test_duplicate_mac_detection(self):
        self.assertEqual(find_duplicate_macs({"10.0.0.1": "m1", "10.0.0.2": "m1", "10.0.0.3": "m2"}), {"m1": ["10.0.0.1", "10.0.0.2"]})

    def test_cycle_builds_hosts_and_exposures(self):
        net = FakeNetwork()
        net.live = {"10.0.0.1": [135, 445, 3389], "10.0.0.2": [80]}
        net.arp = {"10.0.0.2": "00:15:5d:00:00:02"}
        alerts = []
        engine = make_engine(net, whitelist=["00:15:5d:00:00:09"])
        engine._alert = lambda **kw: alerts.append(kw)
        snapshot = engine.run_cycle()
        self.assertEqual(set(snapshot.hosts), {"10.0.0.1", "10.0.0.2"})
        h1 = snapshot.hosts["10.0.0.1"]
        self.assertEqual(h1.asset_status, "unverified")
        self.assertIn("SMBV1-ENABLED", h1.exposures)
        self.assertEqual(snapshot.hosts["10.0.0.2"].asset_status, "rogue")
        self.assertTrue(any(a["dedup_key"].startswith("rogue:") for a in alerts))
        self.assertTrue(any(a["dedup_key"] == "SMBV1-ENABLED" for a in alerts))

    def test_dark_address_space_is_backed_off(self):
        net = FakeNetwork()
        engine = make_engine(net, subnets={"10.0.0.0/28": "Lab"})
        for _ in range(3):
            engine.run_cycle()
        per_cycle = []
        for _ in range(5):
            net.probed.clear()
            snap = engine.run_cycle()
            per_cycle.append(snap.ips_probed)
        self.assertEqual(sum(per_cycle), 14)       # each of 14 dark IPs probed once over 5 cycles
        self.assertTrue(all(n < 14 for n in per_cycle))

    def test_views_merge_fresh_audits_only(self):
        net = FakeNetwork()
        net.live = {"10.0.0.1": [135]}
        snapshot = make_engine(net).run_cycle()
        detection = {"id": "BRUTE-FORCE", "title": "t", "severity": "HIGH", "weight": 7.5, "technique_id": "T1110.001",
                     "technique_name": "n", "tactic": "Credential Access", "evidence": ""}
        fresh = {"10.0.0.1": AuditResult("10.0.0.1", completed_at=1000, success=True, detections=[detection])}
        views = build_host_views(snapshot, fresh, now=1100, audit_stale_after=600)
        self.assertEqual(views[0]["risk_score"], 75.0)
        self.assertFalse(views[0]["compliant"])
        stale = build_host_views(snapshot, fresh, now=5000, audit_stale_after=600)
        self.assertEqual(stale[0]["detections"], [])
        self.assertEqual(stale[0]["wmi_status"], "stale")
        self.assertEqual(summarize(stale)["compliance_percent"], 100.0)


class CollectorTests(unittest.TestCase):
    def scrape(self, engine, auditor=None):
        registry = CollectorRegistry()
        registry.register(SocCollector(engine, auditor or FakeAuditor()))
        return generate_latest(registry).decode()

    def test_offline_hosts_and_fixed_findings_disappear(self):
        net = FakeNetwork()
        net.live = {"10.0.0.1": [23], "10.0.0.2": [80]}
        engine = make_engine(net)
        engine.run_cycle()
        out = self.scrape(engine)
        self.assertIn('target_ip="10.0.0.2"', out)
        self.assertIn('cve_id="TELNET-CLEARTEXT"', out)

        net.live = {"10.0.0.1": [22]}            # 10.0.0.2 left; telnet disabled
        engine.service_interval = 0              # force re-fingerprint
        engine.run_cycle()
        out = self.scrape(engine)
        self.assertNotIn('target_ip="10.0.0.2"', out)
        self.assertNotIn("TELNET-CLEARTEXT", out)
        self.assertIn("total_active_endpoints 1.0", out)

    def test_no_health_value_without_hosts(self):
        engine = make_engine(FakeNetwork())
        self.assertNotIn("network_health_index", self.scrape(engine))  # no data before first sweep
        engine.run_cycle()
        self.assertNotIn("network_health_index ", self.scrape(engine))  # still no hosts: never a fake 100%

    def test_brute_force_counter_exposed(self):
        net = FakeNetwork()
        net.live = {"10.0.0.1": [135]}
        engine = make_engine(net)
        engine.run_cycle()
        out = self.scrape(engine, FakeAuditor(totals={"10.0.0.1": 7}))
        self.assertIn('brute_force_attempts_total{lab_name="Lab A",target_ip="10.0.0.1"} 7.0', out)


class ReportTests(unittest.TestCase):
    def fetcher(self, heartbeat_age=10, now=10_000):
        hostile = '<script>alert("x")</script>|pipe'
        data = {
            "monitor_last_scan_timestamp_seconds": [{"metric": {}, "value": [now, str(now - heartbeat_age)]}],
            "endpoint_risk_score": [{"metric": {"target_ip": "10.0.0.1"}, "value": [now, "81"]}],
            "endpoint_status": [
                {"metric": {"target_ip": "10.0.0.1", "hostname": hostile, "lab_name": "Lab", "mac": "aa", "vendor": "v",
                            "open_services": "SMB", "asset_status": "rogue"}, "value": [now, "1"]},
                {"metric": {"target_ip": "10.0.0.1", "hostname": "dup", "lab_name": "Lab", "asset_status": "rogue"}, "value": [now, "1"]},
            ],
            "vulnerability_exposure": [{"metric": {"target_ip": "10.0.0.1", "cve_id": "SMBV1-ENABLED", "severity": "HIGH",
                                                   "description": "d"}, "value": [now, "1"]}],
            'mitre_attack_technique{evidence="detection"}': [],
            "network_health_index": [{"metric": {}, "value": [now, "0"]}],
        }
        return lambda q: data.get(q, [])

    def test_no_data_never_reports_healthy(self):
        report = collect_report_data(lambda q: None, 60)
        self.assertEqual(report.status, STATUS_NO_DATA)
        self.assertNotIn("100%", render_markdown(report))
        self.assertIn("does not represent", render_html(report))

    def test_stale_detection_and_dedup(self):
        self.assertEqual(collect_report_data(self.fetcher(heartbeat_age=10), 60, now=10_000).status, STATUS_OK)
        report = collect_report_data(self.fetcher(heartbeat_age=4000), 60, now=10_000)
        self.assertEqual(report.status, STATUS_STALE)
        self.assertEqual(len(report.hosts), 1)

    def test_attacker_controlled_values_are_escaped(self):
        report = collect_report_data(self.fetcher(), 60, now=10_000)
        page = render_html(report)
        self.assertNotIn("<script>alert", page)
        self.assertIn("&lt;script&gt;", page)
        self.assertIn("Content-Security-Policy", page)
        self.assertIn('data-asset="rogue"', page)
        markdown = render_markdown(report)
        self.assertNotIn("</script>|pipe", markdown)
        self.assertIn("\\|pipe", markdown)


if __name__ == "__main__":
    unittest.main()
