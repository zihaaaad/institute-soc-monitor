"""Prometheus exposition built fresh from the latest snapshot on every scrape.

A custom collector (instead of long-lived labelled Gauges) means series for
hosts that went offline, findings that were remediated or labels that changed
simply stop being emitted - no manual .remove() bookkeeping, no stale "ONLINE"
rows, no races with background audit threads.
"""
from __future__ import annotations

import time
from typing import Any, Callable, Iterator

from prometheus_client.core import CounterMetricFamily, GaugeMetricFamily
from prometheus_client.registry import Collector

from engine import ASSET_ROGUE, build_host_views, summarize


class SocCollector(Collector):
    def __init__(self, engine: Any, auditor: Any, clock: Callable[[], float] = time.time):
        self.engine = engine
        self.auditor = auditor
        self._clock = clock
        self.audit_stale_after = max(3 * engine.config["settings"]["scan_interval_seconds"], 600)

    def describe(self) -> list:
        return []  # dynamic collector; avoids a collect() call at registration time

    def collect(self) -> Iterator[Any]:
        snapshot = self.engine.latest()
        heartbeat = GaugeMetricFamily("monitor_last_scan_timestamp_seconds", "Unix time the last sweep finished (alert when stale)")
        up = GaugeMetricFamily("monitor_scanning", "1 while a sweep is running")
        up.add_metric([], 1 if self.engine.is_scanning else 0)
        yield up
        if snapshot is None:
            return
        heartbeat.add_metric([], snapshot.finished_at)
        yield heartbeat

        cycle = GaugeMetricFamily("network_scan_duration_seconds", "Duration of the last network sweep")
        cycle.add_metric([], snapshot.duration)
        yield cycle
        probed = GaugeMetricFamily("monitor_ips_probed", "Addresses probed in the last sweep", labels=["scope"])
        probed.add_metric(["probed"], snapshot.ips_probed)
        probed.add_metric(["configured"], snapshot.ips_total)
        yield probed

        views = build_host_views(snapshot, self.auditor.results(), self._clock(), self.audit_stale_after)
        summary = summarize(views)

        for name, doc, value in (
            ("total_active_endpoints", "Live hosts discovered in the last sweep", summary["total_hosts"]),
            ("total_rogue_devices", "Hosts whose MAC is not on the asset whitelist", summary["rogue"]),
            ("total_unverified_devices", "Hosts on routed segments whose MAC cannot be verified", summary["unverified"]),
            ("total_vulnerabilities_detected", "Exposure findings of LOW severity or higher", summary["exposures"]),
            ("total_threat_endpoints", "Hosts with at least one active detection", summary["threat_hosts"]),
        ):
            g = GaugeMetricFamily(name, doc)
            g.add_metric([], value)
            yield g

        if summary["compliance_percent"] is not None:
            health = GaugeMetricFamily("network_health_index",
                                       "Percent of live hosts that are not rogue, have no MEDIUM+ exposure and no detection")
            health.add_metric([], summary["compliance_percent"])
            yield health

        per_lab: dict[tuple[str, str], list[int]] = {}
        status = GaugeMetricFamily("endpoint_status", "Live endpoint inventory (value is always 1)",
                                   labels=["target_ip", "hostname", "subnet", "lab_name", "mac", "vendor", "open_services", "asset_status"])
        latency = GaugeMetricFamily("endpoint_latency_ms", "TCP handshake round-trip time", labels=["target_ip", "subnet", "lab_name"])
        anomaly = GaugeMetricFamily("network_latency_anomaly", "1 when latency exceeds the host's 3-sigma baseline", labels=["target_ip", "subnet"])
        ports = GaugeMetricFamily("endpoint_port_exposure", "Open TCP service (value is always 1)", labels=["target_ip", "subnet", "service"])
        risk = GaugeMetricFamily("endpoint_risk_score", "Weighted endpoint risk score 0-100", labels=["target_ip", "hostname", "subnet", "lab_name"])
        rogue = GaugeMetricFamily("rogue_device_detected", "Unauthorized device (value is always 1)", labels=["target_ip", "mac", "hostname", "lab_name"])
        vulns = GaugeMetricFamily("vulnerability_exposure", "Exposure finding (value is always 1)", labels=["target_ip", "cve_id", "severity", "description"])
        mitre = GaugeMetricFamily("mitre_attack_technique", "ATT&CK technique linked to an exposure or detection",
                                  labels=["target_ip", "technique_id", "technique_name", "tactic", "severity", "evidence"])
        procs = GaugeMetricFamily("suspicious_process_detected", "Blacklisted process running (value is always 1)", labels=["target_ip", "process_name", "lab_name"])
        wmi = GaugeMetricFamily("wmi_audit_success", "1 if the last WMI audit succeeded, 0 if it failed", labels=["target_ip"])
        failed = CounterMetricFamily("brute_force_attempts", "Failed logons (Event ID 4625) observed since monitor start", labels=["target_ip", "lab_name"])
        failed_totals = self.auditor.failed_logon_totals()

        for v in views:
            ip, hostname = v["ip"], v["hostname"] or "(unresolved)"
            mac = v["mac"] or "not visible (routed)"
            status.add_metric([ip, hostname, v["subnet"], v["lab_name"], mac, v["vendor"],
                               ", ".join(v["services"]) or "none", v["asset_status"]], 1)
            if v["latency_ms"] is not None:
                latency.add_metric([ip, v["subnet"], v["lab_name"]], v["latency_ms"])
                anomaly.add_metric([ip, v["subnet"]], 1 if v["latency_anomaly"] else 0)
            for service in v["services"]:
                ports.add_metric([ip, v["subnet"], service], 1)
            risk.add_metric([ip, hostname, v["subnet"], v["lab_name"]], v["risk_score"])
            if v["asset_status"] == ASSET_ROGUE:
                rogue.add_metric([ip, mac, hostname, v["lab_name"]], 1)
            for e in v["exposure_records"]:
                vulns.add_metric([ip, e["id"], str(e["severity"]), str(e["title"])], 1)
                if e["severity"] != "INFO":
                    mitre.add_metric([ip, str(e["technique_id"]), str(e["technique_name"]), str(e["tactic"]), str(e["severity"]), "exposure"], 1)
            for d in v["detections"]:
                mitre.add_metric([ip, str(d["technique_id"]), str(d["technique_name"]), str(d["tactic"]), str(d["severity"]), "detection"], 1)
            for name in v["suspicious_processes"]:
                procs.add_metric([ip, name, v["lab_name"]], 1)
            if v["wmi_success"] is not None:
                wmi.add_metric([ip], 1 if v["wmi_success"] else 0)
            if ip in failed_totals:
                failed.add_metric([ip, v["lab_name"]], failed_totals[ip])

            counts = per_lab.setdefault((v["subnet"], v["lab_name"]), [0, 0])
            counts[0] += 1
            counts[1] += 1 if v["detections"] else 0

        hosts_per_lab = GaugeMetricFamily("active_network_hosts", "Live hosts per subnet", labels=["subnet", "lab_name"])
        threats_per_lab = GaugeMetricFamily("lab_threat_count", "Hosts with detections per subnet", labels=["subnet", "lab_name"])
        for subnet, lab in self.engine.subnets.items():
            live, threats = per_lab.get((subnet, lab), [0, 0])
            hosts_per_lab.add_metric([subnet, lab], live)
            threats_per_lab.add_metric([subnet, lab], threats)

        yield from (status, latency, anomaly, ports, risk, rogue, vulns, mitre, procs, wmi, failed, hosts_per_lab, threats_per_lab)
