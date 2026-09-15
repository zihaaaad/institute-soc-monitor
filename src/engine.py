"""Sweep engine: discovery, asset classification, exposure audit and host views.

Scan-load controls (important on large or fragile networks: BMS, CCTV, VoIP):
* Every cycle each candidate IP gets a short discovery probe (DISCOVERY_PORTS,
  stopping at the first answer). Hosts that were alive are re-checked on their
  last known open port first.
* Full service fingerprinting (PORT_SERVICE_MAP) and the SMBv1 probe run only
  for new hosts and then every `service_scan_interval_seconds`.
* Address space that stays dark is backed off: after DARK_GRACE_CYCLES misses,
  an IP is probed only every DARK_PROBE_EVERY cycles (spread evenly), so a new
  device appears within a few minutes while most dark space is left alone.
* Cycles never overlap.
"""
from __future__ import annotations

import collections
import ipaddress
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Callable

from oui_database import lookup_mac_vendor
from scanner import (
    DISCOVERY_PORTS, PORT_SERVICE_MAP, HostnameResolver, check_smbv1, on_link_networks,
    probe_ports, read_arp_cache, sendarp_mac,
)
from threat_intel import (
    DETECTION_CATALOG, EXPOSURE_CATALOG, LatencyAnomalyDetector, calculate_endpoint_risk_score,
    exposure_ids_for_ports, make_detection, severity_at_least,
)

log = logging.getLogger("monitro.engine")

DARK_GRACE_CYCLES = 3
DARK_PROBE_EVERY = 5
FORGET_HOST_AFTER_SECONDS = 24 * 3600

ASSET_AUTHORIZED = "authorized"   # MAC visible and on the whitelist
ASSET_ROGUE = "rogue"             # MAC visible and NOT on the whitelist
ASSET_UNVERIFIED = "unverified"   # routed segment: MAC not visible, identity unknown
ASSET_UNMANAGED = "unmanaged"     # whitelist empty: no policy to compare against


@dataclass
class HostRecord:
    ip: str
    subnet: str
    lab_name: str
    mac: str | None
    vendor: str
    hostname: str
    hostname_source: str
    open_ports: list[int]
    services: list[str]
    latency_ms: float | None
    latency_anomaly: bool
    asset_status: str
    exposures: list[str]
    network_detections: list[dict[str, object]] = field(default_factory=list)
    first_seen: float = 0.0

    def as_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


@dataclass
class ScanSnapshot:
    cycle: int
    started_at: float
    finished_at: float
    ips_total: int
    ips_probed: int
    hosts: dict[str, HostRecord]

    @property
    def duration(self) -> float:
        return round(self.finished_at - self.started_at, 2)


@dataclass
class _Memory:
    open_ports: list[int] = field(default_factory=list)
    services_checked_at: float = 0.0
    smbv1: bool | None = None
    first_seen: float = 0.0
    last_seen: float = 0.0


def classify_asset(mac: str | None, whitelist: set[str]) -> str:
    if not mac:
        return ASSET_UNVERIFIED
    if not whitelist:
        return ASSET_UNMANAGED
    return ASSET_AUTHORIZED if mac in whitelist else ASSET_ROGUE


def find_duplicate_macs(macs_by_ip: dict[str, str]) -> dict[str, list[str]]:
    """MACs claimed by more than one IP. Normal for routers doing proxy-ARP or
    multi-homed servers, otherwise a classic ARP-spoofing indicator."""
    owners: dict[str, list[str]] = collections.defaultdict(list)
    for ip, mac in macs_by_ip.items():
        owners[mac].append(ip)
    return {mac: sorted(ips) for mac, ips in owners.items() if len(ips) > 1}


class SweepEngine:
    def __init__(
        self,
        config: dict[str, Any],
        alert_sink: Callable[..., Any] | None = None,
        prober: Callable[..., Any] = probe_ports,
        arp_reader: Callable[[], dict[str, str]] = read_arp_cache,
        mac_resolver: Callable[[str], str | None] = sendarp_mac,
        smb_checker: Callable[[str], bool | None] = check_smbv1,
        resolver: HostnameResolver | None = None,
        clock: Callable[[], float] = time.time,
    ):
        self.config = config
        settings = config["settings"]
        self.subnets: dict[str, str] = config["subnets"]
        self.whitelist = set(config.get("asset_whitelist", []))
        self.vuln_config = config.get("vulnerability_audit", {})
        self.timeout = float(settings["probe_timeout_seconds"])
        self.workers = int(settings["probe_workers"])
        self.service_interval = float(settings.get("service_scan_interval_seconds", 900))
        self._alert = alert_sink
        self._prober = prober
        self._arp_reader = arp_reader
        self._mac_resolver = mac_resolver
        self._smb_checker = smb_checker
        self._resolver = resolver or HostnameResolver()
        self._clock = clock

        self._on_link = on_link_networks(config.get("local_ip", ""), list(self.subnets))
        self._targets: list[tuple[str, str, str]] = [
            (str(ip), subnet, lab)
            for subnet, lab in self.subnets.items()
            for ip in ipaddress.IPv4Network(subnet).hosts()
        ]
        self._memory: dict[str, _Memory] = {}
        self._dark_streak: dict[str, int] = {}
        self._detectors: dict[str, LatencyAnomalyDetector] = {}
        self._cycle = 0
        self._cycle_lock = threading.Lock()
        self._snapshot_lock = threading.Lock()
        self._snapshot: ScanSnapshot | None = None

    # ------------------------------------------------------------------
    @property
    def is_scanning(self) -> bool:
        return self._cycle_lock.locked()

    def latest(self) -> ScanSnapshot | None:
        with self._snapshot_lock:
            return self._snapshot

    def try_run_cycle(self) -> ScanSnapshot | None:
        """Run a cycle unless one is already running (returns None then)."""
        if not self._cycle_lock.acquire(blocking=False):
            return None
        try:
            return self._run_cycle()
        finally:
            self._cycle_lock.release()

    def run_cycle(self) -> ScanSnapshot:
        with self._cycle_lock:
            return self._run_cycle()

    # ------------------------------------------------------------------
    def _should_probe(self, ip: str, arp: dict[str, str]) -> bool:
        if ip in arp or ip in self._memory:
            return True
        streak = self._dark_streak.get(ip, 0)
        if streak < DARK_GRACE_CYCLES:
            return True
        return (self._cycle + int(ipaddress.IPv4Address(ip))) % DARK_PROBE_EVERY == 0

    def _is_on_link(self, ip: str) -> bool:
        addr = ipaddress.IPv4Address(ip)
        return any(addr in net for net in self._on_link)

    def _probe_target(self, ip: str, arp: dict[str, str], now: float) -> dict[str, Any] | None:
        memory = self._memory.get(ip)
        mac = arp.get(ip)
        if mac is None and self._is_on_link(ip):
            mac = self._mac_resolver(ip)

        known_ports = list(memory.open_ports) if memory else []
        ports = known_ports + [p for p in DISCOVERY_PORTS if p not in known_ports]
        quick = self._prober(ip, ports, self.timeout, stop_on_first=True)
        if not (quick.responded or mac):
            return None

        needs_services = memory is None or now - memory.services_checked_at >= self.service_interval
        if needs_services:
            full = self._prober(ip, sorted(PORT_SERVICE_MAP), self.timeout, stop_on_first=False)
            open_ports = full.open_ports
            rtt = quick.rtt_ms if quick.rtt_ms is not None else full.rtt_ms
            smbv1 = None
            if 445 in open_ports and self.vuln_config.get("enabled", True) and self.vuln_config.get("check_smbv1", True):
                smbv1 = self._smb_checker(ip)
                if smbv1 is None and memory:
                    smbv1 = memory.smbv1
        else:
            assert memory is not None
            open_ports = sorted(set(memory.open_ports) | set(quick.open_ports))
            rtt = quick.rtt_ms
            smbv1 = memory.smbv1

        hostname, hostname_source = self._resolver.resolve(ip)
        return {"ip": ip, "mac": mac, "open_ports": sorted(open_ports), "rtt": rtt, "smbv1": smbv1,
                "services_refreshed": needs_services, "hostname": hostname, "hostname_source": hostname_source}

    def _run_cycle(self) -> ScanSnapshot:
        self._cycle += 1
        started = self._clock()
        arp = self._arp_reader()
        candidates = [(ip, subnet, lab) for ip, subnet, lab in self._targets if self._should_probe(ip, arp)]
        log.info("Cycle %d: probing %d of %d addresses across %d subnets",
                 self._cycle, len(candidates), len(self._targets), len(self.subnets))

        with ThreadPoolExecutor(max_workers=self.workers, thread_name_prefix="probe") as pool:
            raw = list(pool.map(lambda t: self._probe_target(t[0], arp, started), candidates))

        hosts: dict[str, HostRecord] = {}
        probed_ips = set()
        for (ip, subnet, lab), result in zip(candidates, raw, strict=True):
            probed_ips.add(ip)
            if result is None:
                self._dark_streak[ip] = self._dark_streak.get(ip, 0) + 1
                continue
            self._dark_streak.pop(ip, None)

            memory = self._memory.setdefault(ip, _Memory(first_seen=started))
            memory.last_seen = started
            if result["services_refreshed"]:
                memory.open_ports = result["open_ports"]
                memory.services_checked_at = started
            memory.smbv1 = result["smbv1"]

            anomaly = False
            if result["rtt"] is not None:
                detector = self._detectors.setdefault(ip, LatencyAnomalyDetector())
                anomaly, _ = detector.update(result["rtt"])

            mac = result["mac"]
            hosts[ip] = HostRecord(
                ip=ip, subnet=subnet, lab_name=lab, mac=mac,
                vendor=lookup_mac_vendor(mac),
                hostname=result["hostname"], hostname_source=result["hostname_source"],
                open_ports=result["open_ports"],
                services=[PORT_SERVICE_MAP.get(p, str(p)) for p in result["open_ports"]],
                latency_ms=result["rtt"], latency_anomaly=anomaly,
                asset_status=classify_asset(mac, self.whitelist),
                exposures=exposure_ids_for_ports(result["open_ports"], result["smbv1"], self.vuln_config),
                first_seen=memory.first_seen,
            )

        # Offline hosts keep their port memory for fast re-discovery; forget them after a day.
        for ip in [ip for ip in self._memory if ip in probed_ips and ip not in hosts]:
            if started - self._memory[ip].last_seen > FORGET_HOST_AFTER_SECONDS:
                self._memory.pop(ip, None)
                self._detectors.pop(ip, None)

        duplicates = find_duplicate_macs({ip: h.mac for ip, h in hosts.items() if h.mac})
        for mac, ips in duplicates.items():
            for ip in ips:
                hosts[ip].network_detections.append(make_detection(
                    "ARP-DUPLICATE-MAC", DETECTION_CATALOG["ARP-DUPLICATE-MAC"], f"{mac} claimed by {', '.join(ips)}"))

        snapshot = ScanSnapshot(self._cycle, started, self._clock(), len(self._targets), len(candidates), hosts)
        with self._snapshot_lock:
            self._snapshot = snapshot
        self._raise_network_alerts(snapshot)
        log.info("Cycle %d finished in %.1fs: %d live hosts", snapshot.cycle, snapshot.duration, len(hosts))
        return snapshot

    def _raise_network_alerts(self, snapshot: ScanSnapshot) -> None:
        if not self._alert:
            return
        for h in snapshot.hosts.values():
            name = h.hostname or "unresolved"
            if h.asset_status == ASSET_ROGUE:
                self._alert(title="Unauthorized device on network", severity="HIGH", target_ip=h.ip,
                            dedup_key=f"rogue:{h.mac}",
                            message=f"{name} ({h.ip}, {h.mac}, {h.vendor}) is not on the asset whitelist - {h.lab_name}")
            for fid in h.exposures:
                info = EXPOSURE_CATALOG[fid]
                if severity_at_least(str(info["severity"]), "HIGH"):
                    self._alert(title=str(info["title"]), severity=str(info["severity"]), target_ip=h.ip,
                                dedup_key=fid, message=f"{name} ({h.ip}) in {h.lab_name}. {info['remediation']}")
            for det in h.network_detections:
                self._alert(title=str(det["title"]), severity=str(det["severity"]), target_ip=h.ip,
                            dedup_key=str(det["id"]), message=f"{det['technique_id']} on {h.lab_name}",
                            evidence=str(det["evidence"]))


# ---------------------------------------------------------------------------
# Host views: scan data + WMI audit results -> what dashboards and reports show
# ---------------------------------------------------------------------------
def build_host_views(
    snapshot: ScanSnapshot | None,
    audit_results: dict[str, Any],
    now: float,
    audit_stale_after: float,
) -> list[dict[str, Any]]:
    if snapshot is None:
        return []
    views = []
    for host in snapshot.hosts.values():
        audit = audit_results.get(host.ip)
        fresh_audit = audit if audit and now - audit.completed_at <= audit_stale_after else None
        detections = list(host.network_detections) + (list(fresh_audit.detections) if fresh_audit else [])

        exposure_records = [{"id": fid, **EXPOSURE_CATALOG[fid]} for fid in host.exposures]
        weights = [float(e["weight"]) for e in exposure_records] + [float(d["weight"]) for d in detections]
        is_rogue = host.asset_status == ASSET_ROGUE
        risk = calculate_endpoint_risk_score(weights, is_rogue=is_rogue)
        compliant = (not is_rogue and not detections
                     and not any(severity_at_least(str(e["severity"]), "MEDIUM") for e in exposure_records))

        if audit is None:
            wmi_status = "not audited"
        elif not fresh_audit:
            wmi_status = "stale"
        else:
            wmi_status = "ok" if audit.success else f"failed ({audit.error})"

        views.append({
            **host.as_dict(),
            "exposure_records": exposure_records,
            "detections": detections,
            "suspicious_processes": list(fresh_audit.suspicious_processes) if fresh_audit else [],
            "risk_score": risk,
            "compliant": compliant,
            "wmi_status": wmi_status,
            "wmi_success": None if fresh_audit is None else bool(fresh_audit.success),
        })
    views.sort(key=lambda v: tuple(int(o) for o in v["ip"].split(".")))
    return views


def summarize(views: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(views)
    compliant = sum(1 for v in views if v["compliant"])
    return {
        "total_hosts": total,
        "rogue": sum(1 for v in views if v["asset_status"] == ASSET_ROGUE),
        "unverified": sum(1 for v in views if v["asset_status"] == ASSET_UNVERIFIED),
        "exposures": sum(1 for v in views for e in v["exposure_records"] if severity_at_least(str(e["severity"]), "LOW")),
        "threat_hosts": sum(1 for v in views if v["detections"]),
        "compliance_percent": round(100.0 * compliant / total, 1) if total else None,
    }
