# Open-Source Cyber Threat Intelligence & Anomaly Scoring Algorithms
# Aligned with MITRE ATT&CK Framework & CVSS v3.1 Standards

import math
from typing import Dict, List, Tuple, Any

# ---------------------------------------------------------
# MITRE ATT&CK Framework Knowledge Mapping
# ---------------------------------------------------------
MITRE_TECHNIQUES = {
    "bruteforce": {
        "technique_id": "T1110.001",
        "technique_name": "Brute Force: Password Guessing",
        "tactic": "Credential Access",
        "cvss_base": 7.5,
        "severity": "HIGH"
    },
    "mimikatz.exe": {
        "technique_id": "T1003.001",
        "technique_name": "OS Credential Dumping: LSASS Memory",
        "tactic": "Credential Access",
        "cvss_base": 9.8,
        "severity": "CRITICAL"
    },
    "psexec.exe": {
        "technique_id": "T1569.002",
        "technique_name": "System Services: Service Execution",
        "tactic": "Execution / Lateral Movement",
        "cvss_base": 8.1,
        "severity": "HIGH"
    },
    "netcat.exe": {
        "technique_id": "T1059.003",
        "technique_name": "Command & Scripting: Windows Command Shell",
        "tactic": "Execution / Command & Control",
        "cvss_base": 7.8,
        "severity": "HIGH"
    },
    "nc.exe": {
        "technique_id": "T1059.003",
        "technique_name": "Command & Scripting: Netcat Reverse Shell",
        "tactic": "Command & Control",
        "cvss_base": 7.8,
        "severity": "HIGH"
    },
    "powershell.exe": {
        "technique_id": "T1059.001",
        "technique_name": "Command & Scripting: PowerShell Execution",
        "tactic": "Execution",
        "cvss_base": 5.5,
        "severity": "MEDIUM"
    },
    "cmd.exe": {
        "technique_id": "T1059.003",
        "technique_name": "Command & Scripting: Windows Command Shell",
        "tactic": "Execution",
        "cvss_base": 4.0,
        "severity": "LOW"
    },
    "nmap.exe": {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "Discovery",
        "cvss_base": 6.5,
        "severity": "MEDIUM"
    },
    "wireshark.exe": {
        "technique_id": "T1040",
        "technique_name": "Network Sniffing: Promiscuous Capture",
        "tactic": "Credential Access / Discovery",
        "cvss_base": 6.0,
        "severity": "MEDIUM"
    },
    "tor.exe": {
        "technique_id": "T1090.003",
        "technique_name": "Proxy: Multi-hop Proxy (Anonymization)",
        "tactic": "Command & Control",
        "cvss_base": 7.2,
        "severity": "HIGH"
    },
    "anydesk.exe": {
        "technique_id": "T1219",
        "technique_name": "Remote Access Software (Unsanctioned)",
        "tactic": "Command & Control",
        "cvss_base": 6.8,
        "severity": "MEDIUM"
    },
    "teamviewer.exe": {
        "technique_id": "T1219",
        "technique_name": "Remote Access Software (Unsanctioned)",
        "tactic": "Command & Control",
        "cvss_base": 6.8,
        "severity": "MEDIUM"
    },
    "MS17-010-RISK": {
        "technique_id": "T1210",
        "technique_name": "Exploitation of Remote Services (EternalBlue / SMBv1)",
        "tactic": "Lateral Movement",
        "cvss_base": 9.8,
        "severity": "CRITICAL"
    },
    "RDP-EXPOSURE": {
        "technique_id": "T1021.001",
        "technique_name": "Remote Services: Remote Desktop Protocol",
        "tactic": "Lateral Movement",
        "cvss_base": 6.5,
        "severity": "MEDIUM"
    },
    "CLEARTEXT-HTTP": {
        "technique_id": "T1071.001",
        "technique_name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command & Control",
        "cvss_base": 4.3,
        "severity": "LOW"
    },
    "RPC-DCOM-EXPOSURE": {
        "technique_id": "T1021.003",
        "technique_name": "Remote Services: Distributed Component Object Model",
        "tactic": "Lateral Movement",
        "cvss_base": 5.3,
        "severity": "LOW"
    }
}

# ---------------------------------------------------------
# CVSS 3.1 Quantitative Risk Score Algorithm
# ---------------------------------------------------------
def calculate_endpoint_risk_score(vulnerabilities: List[str], suspicious_processes: List[str], failed_logons: int, is_rogue: bool) -> float:
    """
    Computes a standardized CVSS-based Security Risk Score (0.0 to 100.0).
    Higher score represents elevated cyber risk and attack surface exposure.
    """
    risk_score = 0.0

    # 1. Add vulnerability weights
    for v in vulnerabilities:
        intel = MITRE_TECHNIQUES.get(v, {})
        cvss = intel.get("cvss_base", 3.0)
        risk_score += cvss * 3.5

    # 2. Add active suspicious process weights
    for proc in suspicious_processes:
        intel = MITRE_TECHNIQUES.get(proc.lower(), {})
        cvss = intel.get("cvss_base", 4.0)
        risk_score += cvss * 4.0

    # 3. Add brute-force failed logon penalty
    if failed_logons > 0:
        risk_score += min(failed_logons * 8.0, 35.0)

    # 4. Rogue device unauthorized access penalty
    if is_rogue:
        risk_score += 30.0

    return round(min(risk_score, 100.0), 1)

# ---------------------------------------------------------
# Statistical Anomaly Detection Algorithm (Z-Score)
# ---------------------------------------------------------
class LatencyAnomalyDetector:
    """
    Online Welford algorithm for running mean and standard deviation.
    Flags network anomalies using Z-Score statistical thresholds.
    """
    def __init__(self, z_threshold: float = 3.0):
        self.count = 0
        self.mean = 0.0
        self.m2 = 0.0
        self.z_threshold = z_threshold

    def update(self, latency: float) -> Tuple[bool, float]:
        self.count += 1
        delta = latency - self.mean
        self.mean += delta / self.count
        delta2 = latency - self.mean
        self.m2 += delta * delta2

        if self.count < 10:
            return False, 0.0

        variance = self.m2 / (self.count - 1)
        stdev = math.sqrt(variance) if variance > 0 else 0.001
        z_score = (latency - self.mean) / stdev

        is_anomaly = z_score > self.z_threshold
        return is_anomaly, round(z_score, 2)
