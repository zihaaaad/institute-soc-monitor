import os
import sys
import json
import time
import urllib.request
import urllib.parse
from typing import Dict, List, Any

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
REPORT_MD_PATH = os.path.join(BASE_DIR, "EXECUTIVE_AUDIT_REPORT.md")
REPORT_HTML_PATH = os.path.join(BASE_DIR, "executive_audit_report.html")

import socket

def is_prometheus_up() -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.2)
            return s.connect_ex(("127.0.0.1", 9090)) == 0
    except Exception:
        return False

def fetch_prometheus_metric(query: str) -> List[Dict[str, Any]]:
    if not is_prometheus_up():
        return []
    try:
        url = f"http://localhost:9090/api/v1/query?query={urllib.parse.quote(query)}"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            data = json.loads(resp.read().decode())
            if data.get("status") == "success":
                return data.get("data", {}).get("result", [])
    except Exception:
        pass
    return []

def generate_report():
    print("=" * 75)
    print(" Generating Executive Cyber SOC Compliance & Quality Audit Report...")
    print("=" * 75)

    # 1. Fetch live metrics from Prometheus
    endpoints_raw = fetch_prometheus_metric("endpoint_status")
    vulns_raw = fetch_prometheus_metric("vulnerability_exposure == 1")
    rogues_raw = fetch_prometheus_metric("rogue_device_detected == 1")
    mitre_raw = fetch_prometheus_metric("mitre_attack_technique == 1")
    risk_raw = fetch_prometheus_metric("endpoint_risk_score")
    health_raw = fetch_prometheus_metric("network_health_index")

    total_pcs = len(endpoints_raw)
    total_rogues = len(rogues_raw)
    total_vulns = len(vulns_raw)
    total_mitre = len(mitre_raw)
    
    health_score = 100
    if health_raw:
        try:
            health_score = int(float(health_raw[0].get("value", [0, 100])[1]))
        except Exception:
            health_score = 100
    elif total_pcs > 0:
        health_score = max(100 - (total_rogues * 15 + total_vulns * 5), 0)

    report_time = time.strftime("%Y-%m-%d %H:%M:%S")

    # Group by lab
    labs_breakdown = {}
    for ep in endpoints_raw:
        metric = ep.get("metric", {})
        lab = metric.get("lab_name", "General Lab")
        labs_breakdown[lab] = labs_breakdown.get(lab, 0) + 1

    # 2. Build Markdown Report (Zero Emojis)
    md_content = f"""# Institute Cyber SOC Compliance & Quality Audit Report

* **Generated At:** {report_time}
* **Audit Scope:** Active Network Subnets & Lab Endpoints
* **Network Posture Rating:** {health_score}% ({'OPTIMAL' if health_score >= 90 else 'ELEVATED RISK' if health_score >= 70 else 'CRITICAL ATTENTION REQUIRED'})

---

## 1. Executive Summary & KPIs

| Key Metric | Measured Value | Compliance Status |
| :--- | :--- | :--- |
| **Total Active Workstations** | {total_pcs} Systems | Discovered & Active |
| **Unauthorized / Rogue Devices** | {total_rogues} Devices | {'Action Required' if total_rogues > 0 else 'Compliant'} |
| **Vulnerability & Exposure Risks** | {total_vulns} Findings | {'Remediation Recommended' if total_vulns > 0 else 'Optimal'} |
| **MITRE ATT&CK Threat Detections** | {total_mitre} Indicators | {'Active Threats Flagged' if total_mitre > 0 else 'Zero Threats'} |
| **Monitored Lab Segments** | {len(labs_breakdown)} Subnets | Operational |

---

## 2. Lab Capacity & Utilization Distribution

| Lab / Subnet Segment | Active Workstations | Distribution % | Capacity Status |
| :--- | :--- | :--- | :--- |
"""
    for lab, count in labs_breakdown.items():
        pct = round((count / total_pcs) * 100, 1) if total_pcs > 0 else 0
        md_content += f"| **{lab}** | {count} PCs | {pct}% | Nominal |\n"

    md_content += """
---

## 3. Discovered Active Endpoints Matrix

| IP Address | Computer Name | Lab Location | Hardware MAC | Vendor (OUI) | Open Services |
| :--- | :--- | :--- | :--- | :--- | :--- |
"""
    for ep in endpoints_raw:
        m = ep.get("metric", {})
        md_content += f"| `{m.get('target_ip', '-')}` | {m.get('hostname', '-')} | {m.get('lab_name', '-')} | `{m.get('mac', '-')}` | {m.get('vendor', '-')} | {m.get('open_services', '-')} |\n"

    if vulns_raw:
        md_content += """
---

## 4. Attack Surface & Vulnerability Exposures

| Target IP | Risk / CVE Identifier | Severity Level | Description |
| :--- | :--- | :--- | :--- |
"""
        for v in vulns_raw:
            vm = v.get("metric", {})
            md_content += f"| `{vm.get('target_ip', '-')}` | **{vm.get('cve_id', '-')}** | {vm.get('severity', '-')} | {vm.get('description', '-')} |\n"

    if rogues_raw:
        md_content += """
---

## 5. Rogue & Unauthorized Device Detection Log

| IP Address | Hardware MAC | Hostname | Lab Location | Action Required |
| :--- | :--- | :--- | :--- | :--- |
"""
        for r in rogues_raw:
            rm = r.get("metric", {})
            md_content += f"| `{rm.get('target_ip', '-')}` | `{rm.get('mac', '-')}` | {rm.get('hostname', '-')} | {rm.get('lab_name', '-')} | Inspect Physical Ethernet Port |\n"

    md_content += """
---

## 6. Actionable SOC Remediation Checklist

1. **Rogue Hardware Isolation**: Cross-reference unverified MAC addresses with institute asset records.
2. **Protocol Hardening**: Disable legacy SMBv1 on Windows 10/11 endpoints to mitigate lateral traversal risks.
3. **Remote Desktop Boundary**: Restrict RDP port 3389 access to administrative subnets via Windows Defender Firewall.
4. **Authentication Monitoring**: Review event logs for recurring Event ID 4625 brute-force indicators.

---
*Report generated automatically by Institute Cyber SOC & Agentless Network Monitor.*
"""

    with open(REPORT_MD_PATH, "w", encoding="utf-8") as f:
        f.write(md_content)

    # 3. Build Self-Contained, Dynamic, White-Theme HTML Report (Zero Emojis)
    # Prepare JSON data for client-side search, filtering and sorting
    endpoints_list = []
    for ep in endpoints_raw:
        m = ep.get("metric", {})
        endpoints_list.append({
            "ip": m.get("target_ip", "-"),
            "hostname": m.get("hostname", "-"),
            "lab": m.get("lab_name", "-"),
            "subnet": m.get("subnet", "-"),
            "mac": m.get("mac", "-"),
            "vendor": m.get("vendor", "-"),
            "services": m.get("open_services", "-"),
            "status": "ONLINE"
        })

    vulns_list = []
    for v in vulns_raw:
        vm = v.get("metric", {})
        vulns_list.append({
            "ip": vm.get("target_ip", "-"),
            "cve": vm.get("cve_id", "-"),
            "severity": vm.get("severity", "-"),
            "description": vm.get("description", "-")
        })

    rogues_list = []
    for r in rogues_raw:
        rm = r.get("metric", {})
        rogues_list.append({
            "ip": rm.get("target_ip", "-"),
            "mac": rm.get("mac", "-"),
            "hostname": rm.get("hostname", "-"),
            "lab": rm.get("lab_name", "-")
        })

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Institute Cyber SOC - Executive Quality & Compliance Audit Report</title>
    <style>
        :root {{
            --bg-page: #f8fafc;
            --bg-card: #ffffff;
            --border-color: #e2e8f0;
            --text-main: #0f172a;
            --text-muted: #64748b;
            --primary: #0284c7;
            --primary-hover: #0369a1;
            --success-bg: #ecfdf5;
            --success-text: #065f46;
            --success-border: #a7f3d0;
            --danger-bg: #fef2f2;
            --danger-text: #991b1b;
            --danger-border: #fecaca;
            --warning-bg: #fffbeb;
            --warning-text: #92400e;
            --warning-border: #fde68a;
            --font-stack: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        }}

        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background-color: var(--bg-page);
            color: var(--text-main);
            font-family: var(--font-stack);
            line-height: 1.5;
            padding: 30px;
        }}

        .container {{
            max-width: 1280px;
            margin: 0 auto;
        }}

        /* Header */
        .report-header {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 24px 30px;
            margin-bottom: 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        }}

        .header-title h1 {{
            font-size: 24px;
            font-weight: 700;
            color: var(--text-main);
            letter-spacing: -0.02em;
            margin-bottom: 4px;
        }}

        .header-meta {{
            font-size: 13px;
            color: var(--text-muted);
        }}

        .header-actions button {{
            background: var(--primary);
            color: #ffffff;
            border: none;
            padding: 10px 18px;
            border-radius: 8px;
            font-size: 13px;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.2s;
        }}

        .header-actions button:hover {{
            background: var(--primary-hover);
        }}

        /* KPI Grid */
        .kpi-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}

        .kpi-card {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.04);
        }}

        .kpi-label {{
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.04em;
            color: var(--text-muted);
            margin-bottom: 6px;
        }}

        .kpi-value {{
            font-size: 28px;
            font-weight: 700;
            color: var(--text-main);
        }}

        .kpi-subtext {{
            font-size: 12px;
            margin-top: 4px;
            color: var(--text-muted);
        }}

        /* Badges */
        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 600;
            border: 1px solid transparent;
        }}
        .badge-success {{ background: var(--success-bg); color: var(--success-text); border-color: var(--success-border); }}
        .badge-danger {{ background: var(--danger-bg); color: var(--danger-text); border-color: var(--danger-border); }}
        .badge-warning {{ background: var(--warning-bg); color: var(--warning-text); border-color: var(--warning-border); }}
        .badge-info {{ background: #f0f9ff; color: #0369a1; border-color: #bae6fd; }}

        /* Sections */
        .section-card {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 24px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.04);
        }}

        .section-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 18px;
            padding-bottom: 12px;
            border-bottom: 1px solid var(--border-color);
        }}

        .section-header h2 {{
            font-size: 16px;
            font-weight: 700;
            color: var(--text-main);
        }}

        /* Search & Filter Controls */
        .table-controls {{
            display: flex;
            gap: 12px;
            margin-bottom: 16px;
            align-items: center;
            flex-wrap: wrap;
        }}

        .search-box {{
            flex: 1;
            min-width: 250px;
            padding: 9px 14px;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            font-size: 13px;
            background: #ffffff;
            color: var(--text-main);
            outline: none;
        }}

        .search-box:focus {{
            border-color: var(--primary);
            box-shadow: 0 0 0 2px rgba(2, 132, 199, 0.15);
        }}

        .filter-btn {{
            padding: 8px 14px;
            border: 1px solid var(--border-color);
            border-radius: 6px;
            background: #ffffff;
            font-size: 12px;
            font-weight: 600;
            color: var(--text-muted);
            cursor: pointer;
            transition: all 0.15s;
        }}

        .filter-btn.active {{
            background: var(--primary);
            color: #ffffff;
            border-color: var(--primary);
        }}

        /* Tables */
        .table-wrapper {{
            overflow-x: auto;
            border: 1px solid var(--border-color);
            border-radius: 8px;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
            text-align: left;
        }}

        th {{
            background: #f1f5f9;
            color: #334155;
            font-weight: 600;
            padding: 11px 14px;
            border-bottom: 1px solid var(--border-color);
            cursor: pointer;
            user-select: none;
        }}

        th:hover {{
            background: #e2e8f0;
        }}

        td {{
            padding: 12px 14px;
            border-bottom: 1px solid var(--border-color);
            color: #1e293b;
        }}

        tr:last-child td {{
            border-bottom: none;
        }}

        tr:hover td {{
            background: #f8fafc;
        }}

        code {{
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            background: #f1f5f9;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 12px;
            color: #0f172a;
        }}

        /* Lab Progress Bar Grid */
        .lab-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 14px;
        }}

        .lab-item {{
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 14px;
            background: #ffffff;
        }}

        .lab-title {{
            display: flex;
            justify-content: space-between;
            font-size: 13px;
            font-weight: 600;
            margin-bottom: 8px;
        }}

        .progress-bar-bg {{
            height: 8px;
            background: #e2e8f0;
            border-radius: 9999px;
            overflow: hidden;
        }}

        .progress-bar-fill {{
            height: 100%;
            background: var(--primary);
            border-radius: 9999px;
        }}

        /* Remediation Checklist */
        .checklist {{
            list-style: none;
        }}

        .checklist-item {{
            display: flex;
            align-items: flex-start;
            padding: 10px 0;
            border-bottom: 1px solid var(--border-color);
            font-size: 13px;
        }}

        .checklist-item:last-child {{
            border-bottom: none;
        }}

        .check-num {{
            background: var(--primary);
            color: #ffffff;
            font-weight: 700;
            font-size: 11px;
            border-radius: 50%;
            width: 20px;
            height: 20px;
            display: flex;
            align-items: center;
            justify-content: center;
            margin-right: 12px;
            flex-shrink: 0;
            margin-top: 1px;
        }}

        @media print {{
            body {{ padding: 0; background: #ffffff; }}
            .header-actions, .table-controls {{ display: none; }}
            .section-card {{ box-shadow: none; border: 1px solid #cbd5e1; }}
        }}
    </style>
</head>
<body>

<div class="container">
    <!-- Header -->
    <div class="report-header">
        <div class="header-title">
            <h1>Institute Cyber SOC - Executive Quality & Compliance Audit</h1>
            <div class="header-meta">Audit Timestamp: {report_time} | Scope: Multi-Subnet Workstations & Local Area Network</div>
        </div>
        <div class="header-actions">
            <button onclick="window.print()">Print / Export PDF</button>
        </div>
    </div>

    <!-- KPI Row -->
    <div class="kpi-grid">
        <div class="kpi-card">
            <div class="kpi-label">Active Workstations</div>
            <div class="kpi-value">{total_pcs}</div>
            <div class="kpi-subtext">Online & responding</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-label">Rogue / Unauthorized</div>
            <div class="kpi-value" style="color: {'#991b1b' if total_rogues > 0 else '#065f46'}">{total_rogues}</div>
            <div class="kpi-subtext">{'Unverified MAC devices' if total_rogues > 0 else 'All devices verified'}</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-label">Vulnerability Risks</div>
            <div class="kpi-value" style="color: {'#92400e' if total_vulns > 0 else '#065f46'}">{total_vulns}</div>
            <div class="kpi-subtext">Exposed management ports</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-label">Security Posture Rating</div>
            <div class="kpi-value" style="color: {'#065f46' if health_score >= 90 else '#92400e' if health_score >= 70 else '#991b1b'}">{health_score}%</div>
            <div class="kpi-subtext">{'Optimal posture' if health_score >= 90 else 'Action recommended'}</div>
        </div>
    </div>

    <!-- Lab Capacity & Distribution -->
    <div class="section-card">
        <div class="section-header">
            <h2>Lab Utilization & Capacity Distribution</h2>
            <span class="badge badge-info">{len(labs_breakdown)} Monitored Labs</span>
        </div>
        <div class="lab-grid">
"""
    for lab, count in labs_breakdown.items():
        pct = round((count / total_pcs) * 100, 1) if total_pcs > 0 else 0
        html_content += f"""
            <div class="lab-item">
                <div class="lab-title">
                    <span>{lab}</span>
                    <span>{count} PCs ({pct}%)</span>
                </div>
                <div class="progress-bar-bg">
                    <div class="progress-bar-fill" style="width: {pct}%;"></div>
                </div>
            </div>
"""

    html_content += f"""
        </div>
    </div>

    <!-- Master Endpoint Inventory Table -->
    <div class="section-card">
        <div class="section-header">
            <h2>Master Endpoint & Hardware Inventory Matrix</h2>
            <span class="badge badge-success" id="rowCountBadge">{total_pcs} Systems Active</span>
        </div>

        <div class="table-controls">
            <input type="text" id="searchInput" class="search-box" placeholder="Search by IP, Computer Name, Lab, MAC Address, or Vendor..." onkeyup="filterTable()">
            <button class="filter-btn active" onclick="setFilter('all', this)">All Endpoints</button>
            <button class="filter-btn" onclick="setFilter('rogue', this)">Rogue Devices Only</button>
            <button class="filter-btn" onclick="setFilter('vuln', this)">Vulnerable Hosts Only</button>
        </div>

        <div class="table-wrapper">
            <table id="endpointTable">
                <thead>
                    <tr>
                        <th onclick="sortTable(0)">IP Address</th>
                        <th onclick="sortTable(1)">Computer Name</th>
                        <th onclick="sortTable(2)">Lab / Subnet</th>
                        <th onclick="sortTable(3)">Hardware MAC</th>
                        <th onclick="sortTable(4)">Vendor (OUI)</th>
                        <th onclick="sortTable(5)">Open Services</th>
                        <th onclick="sortTable(6)">Status</th>
                    </tr>
                </thead>
                <tbody id="endpointBody">
"""
    for ep in endpoints_list:
        html_content += f"""
                    <tr>
                        <td><code>{ep['ip']}</code></td>
                        <td><strong>{ep['hostname']}</strong></td>
                        <td>{ep['lab']}</td>
                        <td><code>{ep['mac']}</code></td>
                        <td>{ep['vendor']}</td>
                        <td>{ep['services']}</td>
                        <td><span class="badge badge-success">ONLINE</span></td>
                    </tr>
"""

    html_content += """
                </tbody>
            </table>
        </div>
    </div>

    <!-- Vulnerability Findings Matrix -->
"""
    if vulns_list:
        html_content += """
    <div class="section-card">
        <div class="section-header">
            <h2>Attack Surface & Vulnerability Risk Matrix</h2>
            <span class="badge badge-warning">Action Recommended</span>
        </div>
        <div class="table-wrapper">
            <table>
                <thead>
                    <tr>
                        <th>Target IP</th>
                        <th>Vulnerability / Identifier</th>
                        <th>Severity</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody>
"""
        for v in vulns_list:
            sev_class = "badge-danger" if v['severity'] in ["HIGH", "CRITICAL"] else "badge-warning" if v['severity'] == "MEDIUM" else "badge-info"
            html_content += f"""
                    <tr>
                        <td><code>{v['ip']}</code></td>
                        <td><strong>{v['cve']}</strong></td>
                        <td><span class="badge {sev_class}">{v['severity']}</span></td>
                        <td>{v['description']}</td>
                    </tr>
"""
        html_content += """
                </tbody>
            </table>
        </div>
    </div>
"""

    html_content += """
    <!-- Strategic Remediation Checklist -->
    <div class="section-card">
        <div class="section-header">
            <h2>Strategic SOC Remediation & Security Checklist</h2>
            <span class="badge badge-info">Administrator Guidelines</span>
        </div>
        <ul class="checklist">
            <li class="checklist-item">
                <div class="check-num">1</div>
                <div>
                    <strong>Rogue Hardware Port Inspection</strong>: Cross-reference any unverified MAC addresses with campus physical inventory and isolate unauthorized wireless access points or student devices.
                </div>
            </li>
            <li class="checklist-item">
                <div class="check-num">2</div>
                <div>
                    <strong>SMB Protocol Hardening</strong>: Ensure SMBv1 is disabled across all Windows 10/11 lab workstations to mitigate lateral exploit traversal risks.
                </div>
            </li>
            <li class="checklist-item">
                <div class="check-num">3</div>
                <div>
                    <strong>Remote Desktop Network Boundaries</strong>: Enforce Network Level Authentication (NLA) and restrict RDP port 3389 inbound access to dedicated management subnets.
                </div>
            </li>
            <li class="checklist-item">
                <div class="check-num">4</div>
                <div>
                    <strong>Logon Anomaly Auditing</strong>: Continuously monitor Windows Event ID 4625 failed logon spikes to detect brute-force password guessing attempts in early stages.
                </div>
            </li>
        </ul>
    </div>
</div>

<script>
    // Client-side search and filtering logic
    let currentFilter = 'all';

    function filterTable() {
        const input = document.getElementById('searchInput');
        const filter = input.value.toLowerCase();
        const tbody = document.getElementById('endpointBody');
        const rows = tbody.getElementsByTagName('tr');
        let visibleCount = 0;

        for (let i = 0; i < rows.length; i++) {
            const text = rows[i].textContent.toLowerCase();
            const matchesSearch = text.includes(filter);
            
            if (matchesSearch) {
                rows[i].style.display = '';
                visibleCount++;
            } else {
                rows[i].style.display = 'none';
            }
        }
        document.getElementById('rowCountBadge').innerText = visibleCount + ' Systems Displayed';
    }

    function setFilter(type, btn) {
        currentFilter = type;
        const buttons = document.querySelectorAll('.filter-btn');
        buttons.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');

        const input = document.getElementById('searchInput');
        if (type === 'rogue') {
            input.value = 'Rogue';
        } else if (type === 'vuln') {
            input.value = 'SMB';
        } else {
            input.value = '';
        }
        filterTable();
    }

    function sortTable(columnIndex) {
        const table = document.getElementById('endpointTable');
        const tbody = table.tBodies[0];
        const rows = Array.from(tbody.querySelectorAll('tr'));
        const isAscending = table.getAttribute('data-sort-dir') !== 'asc';

        rows.sort((rowA, rowB) => {
            const cellA = rowA.cells[columnIndex].innerText.trim();
            const cellB = rowB.cells[columnIndex].innerText.trim();
            return isAscending ? cellA.localeCompare(cellB, undefined, {numeric: true}) : cellB.localeCompare(cellA, undefined, {numeric: true});
        });

        table.setAttribute('data-sort-dir', isAscending ? 'asc' : 'desc');
        tbody.append(...rows);
    }
</script>

</body>
</html>
"""

    with open(REPORT_HTML_PATH, "w", encoding="utf-8") as f:
        f.write(html_content)

    print(f"[SUCCESS] High-Quality Executive Audit Report Generated!")
    print(f" -> Markdown: {REPORT_MD_PATH}")
    print(f" -> Dynamic HTML Report: {REPORT_HTML_PATH}")
    print("=" * 75)

if __name__ == "__main__":
    generate_report()
