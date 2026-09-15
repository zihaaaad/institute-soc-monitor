"""Threat knowledge base, endpoint risk scoring and latency anomaly detection.

Two kinds of evidence are kept deliberately separate:

* Exposures  - configuration weaknesses observed from the network (SMBv1 enabled,
               RDP reachable, cleartext protocols). They *enable* an ATT&CK
               technique but are not evidence of an attack.
* Detections - behaviour observed on the endpoint (failed-logon bursts, known
               offensive tooling, malicious command lines). These are the
               signals a SOC analyst triages.

Severity weights are on a 0-10 scale in the spirit of CVSS qualitative ratings.
They are analyst-assigned weights, not computed CVSS base scores.
"""
from __future__ import annotations

import math
import re
from typing import Iterable

SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# ---------------------------------------------------------------------------
# Exposures (network-observed)
# ---------------------------------------------------------------------------
EXPOSURE_CATALOG: dict[str, dict[str, object]] = {
    "SMBV1-ENABLED": {
        "title": "Legacy SMBv1 dialect accepted on TCP/445",
        "severity": "HIGH",
        "weight": 8.1,
        "reference": "MS17-010 (EternalBlue/WannaCry class)",
        "technique_id": "T1210",
        "technique_name": "Exploitation of Remote Services",
        "tactic": "Lateral Movement",
        "remediation": "Disable SMBv1: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol; confirm MS17-010 patches.",
    },
    "TELNET-CLEARTEXT": {
        "title": "Telnet service reachable on TCP/23 (cleartext credentials)",
        "severity": "HIGH",
        "weight": 7.0,
        "reference": "CWE-319",
        "technique_id": "T1040",
        "technique_name": "Network Sniffing",
        "tactic": "Credential Access",
        "remediation": "Disable Telnet; use SSH or an encrypted management channel.",
    },
    "FTP-CLEARTEXT": {
        "title": "FTP service reachable on TCP/21 (cleartext credentials)",
        "severity": "MEDIUM",
        "weight": 5.5,
        "reference": "CWE-319",
        "technique_id": "T1040",
        "technique_name": "Network Sniffing",
        "tactic": "Credential Access",
        "remediation": "Replace FTP with SFTP/FTPS or remove the service.",
    },
    "RDP-EXPOSURE": {
        "title": "Remote Desktop reachable on TCP/3389",
        "severity": "MEDIUM",
        "weight": 5.0,
        "reference": "CIS Controls v8 4.4 / 12.2",
        "technique_id": "T1021.001",
        "technique_name": "Remote Services: Remote Desktop Protocol",
        "tactic": "Lateral Movement",
        "remediation": "Restrict 3389 to a management subnet via Windows Defender Firewall and require NLA.",
    },
    "VNC-EXPOSURE": {
        "title": "VNC remote control reachable on TCP/5900",
        "severity": "MEDIUM",
        "weight": 6.0,
        "reference": "CWE-306 (frequently weak or no authentication)",
        "technique_id": "T1021.005",
        "technique_name": "Remote Services: VNC",
        "tactic": "Lateral Movement",
        "remediation": "Remove VNC or restrict it to a management subnet and enforce strong authentication.",
    },
    "DATABASE-EXPOSURE": {
        "title": "Database listener reachable (MSSQL 1433 / MySQL 3306 / PostgreSQL 5432)",
        "severity": "MEDIUM",
        "weight": 5.5,
        "reference": "CIS Controls v8 12.2",
        "technique_id": "T1210",
        "technique_name": "Exploitation of Remote Services",
        "tactic": "Lateral Movement",
        "remediation": "Bind the database to localhost or restrict access to application servers only.",
    },
    "HTTP-CLEARTEXT": {
        "title": "Unencrypted HTTP service on TCP/80 or TCP/8080",
        "severity": "LOW",
        "weight": 3.0,
        "reference": "CWE-319",
        "technique_id": "T1040",
        "technique_name": "Network Sniffing",
        "tactic": "Credential Access",
        "remediation": "Serve over HTTPS or remove the service if unintended.",
    },
    "RPC-EXPOSURE": {
        "title": "RPC Endpoint Mapper reachable on TCP/135",
        "severity": "INFO",
        "weight": 0.0,
        "reference": "Expected on Windows; restrict at host firewall where possible",
        "technique_id": "T1021.003",
        "technique_name": "Remote Services: Distributed Component Object Model",
        "tactic": "Lateral Movement",
        "remediation": "Limit inbound 135 to management hosts on the Windows firewall.",
    },
}

# ---------------------------------------------------------------------------
# Detections (endpoint-observed via WMI)
# ---------------------------------------------------------------------------
DETECTION_CATALOG: dict[str, dict[str, object]] = {
    "BRUTE-FORCE": {
        "title": "Burst of failed logons (Event ID 4625)",
        "severity": "HIGH", "weight": 7.5,
        "technique_id": "T1110.001", "technique_name": "Brute Force: Password Guessing", "tactic": "Credential Access",
    },
    "PASSWORD-SPRAY": {
        "title": "Failed logons against many accounts (Event ID 4625)",
        "severity": "HIGH", "weight": 8.0,
        "technique_id": "T1110.003", "technique_name": "Brute Force: Password Spraying", "tactic": "Credential Access",
    },
    "CUSTOM-BLACKLIST": {
        "title": "Process on site blacklist",
        "severity": "MEDIUM", "weight": 5.0,
        "technique_id": "N/A", "technique_name": "Site policy violation", "tactic": "Policy",
    },
    "CUSTOM-COMMANDLINE": {
        "title": "Command line matched a site-defined pattern",
        "severity": "MEDIUM", "weight": 5.0,
        "technique_id": "T1059", "technique_name": "Command and Scripting Interpreter", "tactic": "Execution",
    },
    "ARP-DUPLICATE-MAC": {
        "title": "One MAC address answers for several IPs (possible ARP spoofing)",
        "severity": "MEDIUM", "weight": 6.0,
        "technique_id": "T1557.002", "technique_name": "Adversary-in-the-Middle: ARP Cache Poisoning", "tactic": "Credential Access",
    },
}

# Known tooling, keyed by lowercase image name.
PROCESS_DETECTIONS: dict[str, dict[str, object]] = {
    "mimikatz.exe": {"severity": "CRITICAL", "weight": 9.5, "technique_id": "T1003.001",
                     "technique_name": "OS Credential Dumping: LSASS Memory", "tactic": "Credential Access"},
    "procdump.exe": {"severity": "HIGH", "weight": 7.0, "technique_id": "T1003.001",
                     "technique_name": "OS Credential Dumping: LSASS Memory", "tactic": "Credential Access"},
    "lazagne.exe": {"severity": "HIGH", "weight": 8.0, "technique_id": "T1555",
                    "technique_name": "Credentials from Password Stores", "tactic": "Credential Access"},
    "rubeus.exe": {"severity": "CRITICAL", "weight": 9.0, "technique_id": "T1558",
                   "technique_name": "Steal or Forge Kerberos Tickets", "tactic": "Credential Access"},
    "sharphound.exe": {"severity": "HIGH", "weight": 7.5, "technique_id": "T1087.002",
                       "technique_name": "Account Discovery: Domain Account", "tactic": "Discovery"},
    "psexec.exe": {"severity": "HIGH", "weight": 7.5, "technique_id": "T1569.002",
                   "technique_name": "System Services: Service Execution", "tactic": "Execution"},
    "psexesvc.exe": {"severity": "HIGH", "weight": 8.0, "technique_id": "T1569.002",
                     "technique_name": "System Services: Service Execution", "tactic": "Lateral Movement"},
    "netcat.exe": {"severity": "HIGH", "weight": 7.0, "technique_id": "T1095",
                   "technique_name": "Non-Application Layer Protocol", "tactic": "Command and Control"},
    "nc.exe": {"severity": "HIGH", "weight": 7.0, "technique_id": "T1095",
               "technique_name": "Non-Application Layer Protocol", "tactic": "Command and Control"},
    "ncat.exe": {"severity": "HIGH", "weight": 7.0, "technique_id": "T1095",
                 "technique_name": "Non-Application Layer Protocol", "tactic": "Command and Control"},
    "tor.exe": {"severity": "HIGH", "weight": 7.0, "technique_id": "T1090.003",
                "technique_name": "Proxy: Multi-hop Proxy", "tactic": "Command and Control"},
    "nmap.exe": {"severity": "MEDIUM", "weight": 5.5, "technique_id": "T1046",
                 "technique_name": "Network Service Discovery", "tactic": "Discovery"},
    "wireshark.exe": {"severity": "MEDIUM", "weight": 5.0, "technique_id": "T1040",
                      "technique_name": "Network Sniffing", "tactic": "Credential Access"},
    "anydesk.exe": {"severity": "MEDIUM", "weight": 5.0, "technique_id": "T1219",
                    "technique_name": "Remote Access Software", "tactic": "Command and Control"},
}

# Unified dictionary combining all catalogs for technique lookup
MITRE_TECHNIQUES: dict[str, dict[str, object]] = {}
MITRE_TECHNIQUES.update(EXPOSURE_CATALOG)
MITRE_TECHNIQUES.update(DETECTION_CATALOG)
MITRE_TECHNIQUES.update(PROCESS_DETECTIONS)


# Living-off-the-land command lines. powershell.exe / cmd.exe running is normal;
# these specific argument patterns are not.
COMMANDLINE_RULES: list[dict[str, object]] = [
    {"rule_id": "PS-ENCODED", "pattern": re.compile(r"(?i)powershell(\.exe)?\b.*\s-(e|en|enc|enco|encod|encode|encodedcommand)\s+[a-z0-9+/=]{16,}"),
     "severity": "HIGH", "weight": 7.5, "technique_id": "T1027", "technique_name": "Obfuscated Files or Information", "tactic": "Defense Evasion"},
    {"rule_id": "PS-DOWNLOAD-CRADLE", "pattern": re.compile(r"(?i)(downloadstring|downloadfile|invoke-webrequest|\biwr\b|net\.webclient|start-bitstransfer).*(iex|invoke-expression)|(iex|invoke-expression).*(downloadstring|net\.webclient)"),
     "severity": "HIGH", "weight": 8.0, "technique_id": "T1059.001", "technique_name": "Command and Scripting Interpreter: PowerShell", "tactic": "Execution"},
    {"rule_id": "PS-HIDDEN-WINDOW", "pattern": re.compile(r"(?i)powershell(\.exe)?\b.*\s-(w|win|window|windowstyle)\s+hidden"),
     "severity": "MEDIUM", "weight": 5.5, "technique_id": "T1564.003", "technique_name": "Hide Artifacts: Hidden Window", "tactic": "Defense Evasion"},
    {"rule_id": "CERTUTIL-DOWNLOAD", "pattern": re.compile(r"(?i)certutil(\.exe)?\b.*-urlcache"),
     "severity": "HIGH", "weight": 7.0, "technique_id": "T1105", "technique_name": "Ingress Tool Transfer", "tactic": "Command and Control"},
    {"rule_id": "LSASS-MINIDUMP", "pattern": re.compile(r"(?i)comsvcs(\.dll)?\W.*minidump"),
     "severity": "CRITICAL", "weight": 9.5, "technique_id": "T1003.001", "technique_name": "OS Credential Dumping: LSASS Memory", "tactic": "Credential Access"},
    {"rule_id": "SHADOW-COPY-DELETE", "pattern": re.compile(r"(?i)(vssadmin(\.exe)?\b.*delete\s+shadows|wmic(\.exe)?\b.*shadowcopy\s+delete)"),
     "severity": "CRITICAL", "weight": 9.0, "technique_id": "T1490", "technique_name": "Inhibit System Recovery", "tactic": "Impact"},
    {"rule_id": "BITSADMIN-TRANSFER", "pattern": re.compile(r"(?i)bitsadmin(\.exe)?\b.*/transfer"),
     "severity": "MEDIUM", "weight": 6.0, "technique_id": "T1197", "technique_name": "BITS Jobs", "tactic": "Defense Evasion"},
]


def severity_at_least(severity: str, minimum: str) -> bool:
    return SEVERITY_ORDER.get(severity.upper(), 0) >= SEVERITY_ORDER[minimum]


def make_detection(detection_id: str, info: dict[str, object], evidence: str = "") -> dict[str, object]:
    """Normalise a catalog entry into the detection record shared by metrics, alerts and reports."""
    return {
        "id": detection_id,
        "title": str(info.get("title", detection_id)),
        "severity": str(info.get("severity", "MEDIUM")),
        "weight": float(info.get("weight", 5.0)),  # type: ignore[arg-type]
        "technique_id": str(info.get("technique_id", "N/A")),
        "technique_name": str(info.get("technique_name", "Unknown")),
        "tactic": str(info.get("tactic", "Unknown")),
        "evidence": evidence[:500],
    }


def exposure_ids_for_ports(open_ports: Iterable[int], smbv1: bool | None, vuln_config: dict[str, object]) -> list[str]:
    """Map fingerprinted TCP ports (and the SMBv1 probe result) to exposure findings."""
    if not vuln_config.get("enabled", True):
        return []
    ports = set(open_ports)
    findings: list[str] = []
    if smbv1 and vuln_config.get("check_smbv1", True):
        findings.append("SMBV1-ENABLED")
    if vuln_config.get("check_cleartext_protocols", True):
        if 23 in ports:
            findings.append("TELNET-CLEARTEXT")
        if 21 in ports:
            findings.append("FTP-CLEARTEXT")
        if ports & {80, 8080, 8000, 8888}:
            findings.append("HTTP-CLEARTEXT")
    if 3389 in ports and vuln_config.get("check_rdp_exposure", True):
        findings.append("RDP-EXPOSURE")
    if 5900 in ports:
        findings.append("VNC-EXPOSURE")
    if ports & {1433, 3306, 5432}:
        findings.append("DATABASE-EXPOSURE")
    if 135 in ports and vuln_config.get("check_rpc_mapper", True):
        findings.append("RPC-EXPOSURE")
    return findings


def calculate_endpoint_risk_score(findings_or_weights: Iterable[object], is_rogue: bool = False) -> float:
    """Combine finding weights (0-10 each) or finding identifiers into a 0-100 endpoint risk score.

    The worst finding counts fully and each additional one counts half as much
    as the previous, so ten LOW findings cannot outrank one CRITICAL, and the
    score does not saturate on ordinary Windows hosts.
    """
    weights: list[float] = []
    for item in findings_or_weights:
        if isinstance(item, (int, float)):
            weights.append(float(item))
        elif isinstance(item, str) and item in MITRE_TECHNIQUES:
            w = MITRE_TECHNIQUES[item].get("weight", 0.0)
            weights.append(float(w))
        elif isinstance(item, str) and item.lower() in MITRE_TECHNIQUES:
            w = MITRE_TECHNIQUES[item.lower()].get("weight", 0.0)
            weights.append(float(w))

    score = 0.0
    for rank, weight in enumerate(sorted((w for w in weights if w > 0), reverse=True)):
        score += weight * 10.0 / (2 ** rank)
    if is_rogue:
        score += 30.0
    return round(min(score, 100.0), 1)



class LatencyAnomalyDetector:
    """Welford running mean/variance with a z-score threshold.

    Fed with TCP handshake round-trip time for a single host, so the baseline
    is per endpoint. A minimum absolute deviation stops sub-millisecond jitter
    on quiet LANs from being reported as a 3-sigma event.
    """

    def __init__(self, z_threshold: float = 3.0, min_samples: int = 10, min_delta_ms: float = 15.0):
        self.count = 0
        self.mean = 0.0
        self._m2 = 0.0
        self.z_threshold = z_threshold
        self.min_samples = min_samples
        self.min_delta_ms = min_delta_ms

    def update(self, latency_ms: float) -> tuple[bool, float]:
        # Score against the baseline *before* folding in the new sample.
        is_anomaly, z_score = False, 0.0
        if self.count >= self.min_samples:
            variance = self._m2 / (self.count - 1)
            stdev = math.sqrt(variance) if variance > 0 else 0.0
            delta = latency_ms - self.mean
            if stdev > 0:
                z_score = delta / stdev
            elif delta > 0:
                z_score = math.inf
            is_anomaly = z_score > self.z_threshold and delta >= self.min_delta_ms

        self.count += 1
        d1 = latency_ms - self.mean
        self.mean += d1 / self.count
        self._m2 += d1 * (latency_ms - self.mean)
        return is_anomaly, (round(z_score, 2) if math.isfinite(z_score) else 999.0)
