"""Agentless endpoint auditing over remote WMI (DCOM).

Security controls:
* Credentials are only ever sent to hosts whose MAC is on the asset whitelist
  (or explicitly allowed unverified hosts). Authenticating to an unknown device
  hands it an NTLM challenge-response that can be cracked or relayed.
* Connections request packet privacy (encrypted, integrity-protected DCOM).
* A bounded worker pool and per-host in-flight tracking stop hung DCOM
  connections from piling up threads every cycle.

Detection logic lives in pure functions (analyze_failed_logons,
analyze_processes) so it can be unit tested without Windows.
"""
from __future__ import annotations

import collections
import ipaddress
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Iterable, Pattern

from threat_intel import COMMANDLINE_RULES, DETECTION_CATALOG, PROCESS_DETECTIONS, make_detection

log = logging.getLogger("monitro.wmi")

WBEM_FLAG_RETURN_IMMEDIATELY = 0x10
WBEM_FLAG_FORWARD_ONLY = 0x20
WBEM_FLAG_CONNECT_USE_MAX_WAIT = 0x80  # caps ConnectServer at 2 minutes instead of forever
WBEM_IMPERSONATION_IMPERSONATE = 3
WBEM_AUTHENTICATION_PKT_PRIVACY = 6

# Win32_NTLogEvent.InsertionStrings layout for Security event 4625
IDX_TARGET_USER = 5
IDX_TARGET_DOMAIN = 6
IDX_LOGON_TYPE = 10
IDX_SOURCE_IP = 19


@dataclass
class FailedLogonEvent:
    record: int
    target_user: str
    source_ip: str
    logon_type: str


@dataclass
class FailedLogonAnalysis:
    new_events: int
    max_record: int | None
    detections: list[dict[str, object]]
    top_sources: list[tuple[str, int]]


@dataclass
class AuditResult:
    ip: str
    completed_at: float
    success: bool
    error: str = ""
    new_failed_logons: int = 0
    detections: list[dict[str, object]] = field(default_factory=list)
    suspicious_processes: list[str] = field(default_factory=list)


def wmi_datetime(dt: datetime) -> str:
    """CIM_DATETIME in UTC, e.g. 20260914153000.000000+000."""
    return dt.astimezone(timezone.utc).strftime("%Y%m%d%H%M%S.000000+000")


def _clean_source(value: str) -> str:
    value = (value or "").strip()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return "local/unknown"


def analyze_failed_logons(
    events: Iterable[FailedLogonEvent],
    last_record: int | None,
    brute_force_threshold: int,
    spray_account_threshold: int,
) -> FailedLogonAnalysis:
    """Only events newer than last_record count, so repeated audits never double count."""
    fresh = [e for e in events if last_record is None or e.record > last_record]
    max_record = max((e.record for e in fresh), default=last_record)

    by_source: dict[str, set[str]] = collections.defaultdict(set)
    counts: collections.Counter[str] = collections.Counter()
    for e in fresh:
        src = _clean_source(e.source_ip)
        counts[src] += 1
        by_source[src].add(e.target_user.lower())

    top_sources = counts.most_common(5)
    detections: list[dict[str, object]] = []
    sources_text = ", ".join(f"{src} x{n}" for src, n in top_sources)

    sprayers = [src for src, accounts in by_source.items() if len(accounts) >= spray_account_threshold]
    if sprayers:
        worst = max(sprayers, key=lambda s: len(by_source[s]))
        detections.append(make_detection(
            "PASSWORD-SPRAY", DETECTION_CATALOG["PASSWORD-SPRAY"],
            f"{len(by_source[worst])} distinct accounts from {worst}; sources: {sources_text}"))
    if len(fresh) >= brute_force_threshold:
        detections.append(make_detection(
            "BRUTE-FORCE", DETECTION_CATALOG["BRUTE-FORCE"],
            f"{len(fresh)} failed logons since last audit; sources: {sources_text}"))

    return FailedLogonAnalysis(len(fresh), max_record, detections, top_sources)


def analyze_processes(
    processes: Iterable[dict[str, Any]],
    blacklist: Iterable[str],
    extra_patterns: Iterable[Pattern[str]] = (),
) -> tuple[list[dict[str, object]], list[str]]:
    """Return (detections, suspicious process names) for a process listing.

    Image names are trivially renamed by attackers, so command-line rules are
    the stronger signal; both are reported.
    """
    blacklist = {b.lower() for b in blacklist}
    extra_patterns = list(extra_patterns)
    detections: dict[str, dict[str, object]] = {}
    names: set[str] = set()

    for proc in processes:
        name = str(proc.get("name") or "").lower()
        cmdline = str(proc.get("cmdline") or "")
        pid = proc.get("pid")

        if name and name in blacklist:
            names.add(name)
            info = PROCESS_DETECTIONS.get(name, DETECTION_CATALOG["CUSTOM-BLACKLIST"])
            key = f"PROC:{name}"
            detections.setdefault(key, make_detection(key, {**info, "title": f"Suspicious binary {name}"}, f"pid {pid}: {cmdline[:300]}"))

        if not cmdline:
            continue
        for rule in COMMANDLINE_RULES:
            if rule["pattern"].search(cmdline):  # type: ignore[union-attr]
                key = str(rule["rule_id"])
                detections.setdefault(key, make_detection(key, {**rule, "title": f"Suspicious command line ({key})"}, f"{name} pid {pid}: {cmdline[:300]}"))
        for pattern in extra_patterns:
            if pattern.search(cmdline):
                detections.setdefault("CUSTOM-COMMANDLINE", make_detection(
                    "CUSTOM-COMMANDLINE", DETECTION_CATALOG["CUSTOM-COMMANDLINE"], f"{name} pid {pid}: {cmdline[:300]}"))

    return list(detections.values()), sorted(names)


# ---------------------------------------------------------------------------
# COM layer (Windows only)
# ---------------------------------------------------------------------------
class WmiSession:
    def __init__(self, host: str, user: str, password: str, authority: str = ""):
        import win32com.client  # pywin32; imported lazily so analysis code stays portable

        locator = win32com.client.Dispatch("WbemScripting.SWbemLocator")
        self._svc = locator.ConnectServer(host, r"root\cimv2", user, password, "", authority or "",
                                          WBEM_FLAG_CONNECT_USE_MAX_WAIT, None)
        self._svc.Security_.ImpersonationLevel = WBEM_IMPERSONATION_IMPERSONATE
        self._svc.Security_.AuthenticationLevel = WBEM_AUTHENTICATION_PKT_PRIVACY

    def query(self, wql: str) -> list[Any]:
        results = self._svc.ExecQuery(wql, "WQL", WBEM_FLAG_RETURN_IMMEDIATELY | WBEM_FLAG_FORWARD_ONLY)
        # Forward-only sets cannot report Count, so list(results) (which calls len()) fails; enumerate instead.
        return [item for item in results]


def fetch_failed_logons(session: WmiSession, since: datetime) -> list[FailedLogonEvent]:
    wql = ("SELECT RecordNumber, InsertionStrings FROM Win32_NTLogEvent "
           f"WHERE Logfile = 'Security' AND EventCode = 4625 AND TimeGenerated >= '{wmi_datetime(since)}'")
    events = []
    for item in session.query(wql):
        strings = list(item.InsertionStrings or [])
        user = _insertion_string(strings, IDX_TARGET_USER)
        domain = _insertion_string(strings, IDX_TARGET_DOMAIN)
        events.append(FailedLogonEvent(
            record=int(item.RecordNumber),
            target_user=f"{domain}\\{user}" if domain and domain != "-" else user,
            source_ip=_insertion_string(strings, IDX_SOURCE_IP),
            logon_type=_insertion_string(strings, IDX_LOGON_TYPE),
        ))
    return events


def _insertion_string(strings: list[Any], index: int) -> str:
    return str(strings[index]) if index < len(strings) and strings[index] is not None else ""


def fetch_processes(session: WmiSession) -> list[dict[str, Any]]:
    return [{"name": p.Name, "pid": p.ProcessId, "cmdline": p.CommandLine}
            for p in session.query("SELECT Name, ProcessId, CommandLine FROM Win32_Process")]


def _com_initialize() -> Callable[[], None]:
    try:
        import pythoncom
    except ImportError:
        return lambda: None
    pythoncom.CoInitializeEx(pythoncom.COINIT_MULTITHREADED)
    return pythoncom.CoUninitialize


# ---------------------------------------------------------------------------
# Coordinator
# ---------------------------------------------------------------------------
SessionFactory = Callable[[str, str, str, str], Any]


class WmiAuditor:
    def __init__(
        self,
        config: dict[str, Any],
        alert_sink: Callable[..., Any] | None = None,
        session_factory: SessionFactory | None = None,
        clock: Callable[[], float] = time.time,
    ):
        creds = config.get("credentials", {})
        self.user = str(creds.get("windows_user") or "")
        self.password = str(creds.get("windows_password") or "")
        self.authority = str(creds.get("windows_authority") or "")
        self.settings = config.get("wmi_audit", {})
        self.blacklist = config.get("suspicious_processes", [])
        self.extra_patterns = config.get("compiled_commandline_patterns", [])
        self.local_ip = config.get("local_ip", "")
        self.interval = float(config.get("settings", {}).get("scan_interval_seconds", 60))
        self._alert = alert_sink
        self._session_factory = session_factory or (lambda h, u, p, a: WmiSession(h, u, p, a))
        self._clock = clock
        self._pool = ThreadPoolExecutor(max_workers=int(self.settings.get("max_concurrent_audits", 16)),
                                        thread_name_prefix="wmi-audit")
        self._lock = threading.Lock()
        self._in_flight: set[str] = set()
        self._results: dict[str, AuditResult] = {}
        self._last_record: dict[str, int | None] = {}
        self._failed_logon_totals: dict[str, int] = {}
        self._warned_disabled = False

    @property
    def enabled(self) -> bool:
        return bool(self.settings.get("enabled", True) and self.user and self.password)

    def eligibility(self, host: dict[str, Any]) -> tuple[bool, str]:
        if not self.enabled:
            return False, "wmi audit disabled or no credentials"
        if host["ip"] == self.local_ip:
            return False, "local host"
        if 135 not in host.get("open_ports", []):
            return False, "RPC 135 not reachable"
        status = host.get("asset_status")
        if status == "authorized":
            return True, ""
        if status in ("unverified", "unmanaged") and self.settings.get("audit_unverified_hosts", False):
            return True, ""
        return False, f"asset_status={status}; credentials are never sent to unapproved devices"

    def submit(self, hosts: Iterable[dict[str, Any]]) -> int:
        if not self.enabled:
            if not self._warned_disabled:
                log.info("WMI endpoint auditing inactive (enable wmi_audit and set MONITRO_WINDOWS_USER/PASSWORD).")
                self._warned_disabled = True
            return 0
        now = self._clock()
        submitted = 0
        for host in hosts:
            ok, _ = self.eligibility(host)
            if not ok:
                continue
            ip = host["ip"]
            with self._lock:
                last = self._results.get(ip)
                if ip in self._in_flight or (last and now - last.completed_at < self.interval * 0.9):
                    continue
                self._in_flight.add(ip)
            self._pool.submit(self._audit, ip, str(host.get("lab_name", "")))
            submitted += 1
        return submitted

    def results(self) -> dict[str, AuditResult]:
        with self._lock:
            return dict(self._results)

    def failed_logon_totals(self) -> dict[str, int]:
        with self._lock:
            return dict(self._failed_logon_totals)

    def shutdown(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)

    # ------------------------------------------------------------------
    def _audit(self, ip: str, lab_name: str) -> None:
        uninit = _com_initialize()
        result = AuditResult(ip=ip, completed_at=self._clock(), success=False)
        try:
            session = self._session_factory(ip, self.user, self.password, self.authority)
            result = self._run_checks(session, ip)
        except Exception as e:  # COM errors are diverse; record them, never crash the pool
            result.error = type(e).__name__ + (f": {e.args[1]}" if getattr(e, "args", None) and len(e.args) > 1 else "")
            log.info("WMI audit of %s failed: %s", ip, result.error)
        finally:
            with self._lock:
                self._results[ip] = result
                self._in_flight.discard(ip)
            uninit()

        for det in result.detections:
            if self._alert:
                self._alert(title=str(det["title"]), severity=str(det["severity"]), target_ip=ip,
                            dedup_key=str(det["id"]),
                            message=f"{det['technique_id']} {det['technique_name']} on {ip} ({lab_name})",
                            evidence=str(det.get("evidence", "")))

    def _run_checks(self, session: Any, ip: str) -> AuditResult:
        now = self._clock()
        result = AuditResult(ip=ip, completed_at=now, success=True)
        errors = []

        lookback = timedelta(minutes=float(self.settings.get("event_lookback_minutes", 15)))
        since = datetime.fromtimestamp(now, tz=timezone.utc) - lookback
        try:
            events = fetch_failed_logons(session, since)
            with self._lock:
                last = self._last_record.get(ip)
            analysis = analyze_failed_logons(
                events, last,
                int(self.settings.get("brute_force_threshold", 10)),
                int(self.settings.get("password_spray_account_threshold", 5)))
            with self._lock:
                self._last_record[ip] = analysis.max_record
                self._failed_logon_totals[ip] = self._failed_logon_totals.get(ip, 0) + analysis.new_events
            result.new_failed_logons = analysis.new_events
            result.detections.extend(analysis.detections)
        except Exception as e:
            errors.append(f"eventlog: {type(e).__name__}")

        try:
            detections, names = analyze_processes(fetch_processes(session), self.blacklist, self.extra_patterns)
            result.detections.extend(detections)
            result.suspicious_processes = names
        except Exception as e:
            errors.append(f"processes: {type(e).__name__}")

        if errors:
            result.error = "; ".join(errors)
            result.success = len(errors) < 2
        return result
