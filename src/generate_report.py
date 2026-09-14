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

def fetch_prometheus_metric(query: str) -> List[Dict[str, Any]]:
    try:
        url = f"http://localhost:9090/api/v1/query?query={urllib.parse.quote(query)}"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode())
            if data.get("status") == "success":
                return data.get("data", {}).get("result", [])
    except Exception as e:
        pass
    return []

def generate_report():
    print("=" * 70)
    print(" Generating Institute Cyber SOC Compliance & Audit Report...")
    print("=" * 70)

    # 1. Fetch live metrics from Prometheus
    endpoints_raw = fetch_prometheus_metric("endpoint_status")
    vulns_raw = fetch_prometheus_metric("vulnerability_exposure")
    rogues_raw = fetch_prometheus_metric("rogue_device_detected == 1")
    brute_raw = fetch_prometheus_metric("sum by (target_ip, lab_name) (increase(brute_force_attempts_total[1h])) > 0")

    total_pcs = len(endpoints_raw)
    total_rogues = len(rogues_raw)
    total_vulns = len(vulns_raw)
    report_time = time.strftime("%Y-%m-%d %H:%M:%S")

    # Group by lab
    labs_breakdown = {}
    for ep in endpoints_raw:
        metric = ep.get("metric", {})
        lab = metric.get("lab_name", "Unknown Lab")
        labs_breakdown[lab] = labs_breakdown.get(lab, 0) + 1

    # 2. Build Markdown Report
    md_content = f"""# Institute Cyber SOC & Network Audit Report

* **Generated At:** {report_time}
* **Audit Scope:** Active Subnets & Windows Lab Workstations
* **Compliance Status:** {'CRITICAL ATTENTION REQUIRED' if total_rogues > 0 or total_vulns > 0 else 'HEALTHY & COMPLIANT'}

---

## 1. Executive Summary

| Key Metric | Value | Compliance Status |
| :--- | :--- | :--- |
| **Total Active Endpoints Discovered** | {total_pcs} PCs | Active |
| **Unauthorized / Rogue Devices** | {total_rogues} | {'ALERT' if total_rogues > 0 else 'Compliant'} |
| **Vulnerability & Exposure Risks** | {total_vulns} | {'Review Required' if total_vulns > 0 else 'Optimal'} |
| **Monitored Lab Segments** | {len(labs_breakdown)} Labs | Operational |

---

## 2. Lab Capacity & Endpoint Distribution

| Lab / Subnet Segment | Active Workstations | Distribution % |
| :--- | :--- | :--- |
"""
    for lab, count in labs_breakdown.items():
        pct = round((count / total_pcs) * 100, 1) if total_pcs > 0 else 0
        md_content += f"| **{lab}** | {count} | {pct}% |\n"

    md_content += """
---

## 3. Discovered Active Endpoints Matrix

| IP Address | Computer Name | Subnet / Lab | Hardware MAC | Vendor | Open Services |
| :--- | :--- | :--- | :--- | :--- | :--- |
"""
    for ep in endpoints_raw:
        m = ep.get("metric", {})
        md_content += f"| `{m.get('target_ip', '-')}` | {m.get('hostname', '-')} | {m.get('lab_name', '-')} | `{m.get('mac', '-')}` | {m.get('vendor', '-')} | {m.get('open_services', '-')} |\n"

    if vulns_raw:
        md_content += """
---

## 4. High-Risk Vulnerabilities & Protocol Exposures

| Target IP | Risk / CVE Identifier | Severity | Description |
| :--- | :--- | :--- | :--- |
"""
        for v in vulns_raw:
            vm = v.get("metric", {})
            md_content += f"| `{vm.get('target_ip', '-')}` | **{vm.get('cve_id', '-')}** | {vm.get('severity', '-')} | {vm.get('description', '-')} |\n"

    if rogues_raw:
        md_content += """
---

## 5. Rogue & Unauthorized Device Alarms

| IP Address | Hardware MAC | Computer Name | Lab Location | Action Required |
| :--- | :--- | :--- | :--- | :--- |
"""
        for r in rogues_raw:
            rm = r.get("metric", {})
            md_content += f"| `{rm.get('target_ip', '-')}` | `{rm.get('mac', '-')}` | {rm.get('hostname', '-')} | {rm.get('lab_name', '-')} | Inspect Physical Port |\n"

    md_content += """
---
*Report generated automatically by Institute Cyber SOC & Agentless Monitor.*
"""

    with open(REPORT_MD_PATH, "w", encoding="utf-8") as f:
        f.write(md_content)

    # 3. Build Self-Contained HTML Report
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Institute SOC Executive Audit Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 40px; background: #0f172a; color: #f8fafc; }}
        h1, h2, h3 {{ color: #38bdf8; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; background: #1e293b; border-radius: 8px; overflow: hidden; }}
        th, td {{ padding: 12px 16px; text-align: left; border-bottom: 1px solid #334155; }}
        th {{ background: #0ea5e9; color: #ffffff; font-weight: 600; text-transform: uppercase; font-size: 12px; }}
        tr:hover {{ background: #334155; }}
        .card-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 30px; }}
        .card {{ background: #1e293b; padding: 20px; border-radius: 8px; border: 1px solid #334155; }}
        .card-val {{ font-size: 28px; font-weight: 700; color: #38bdf8; margin-top: 8px; }}
    </style>
</head>
<body>
    <h1>Institute Cyber SOC & Network Audit Report</h1>
    <p>Generated At: <strong>{report_time}</strong> | Scope: <strong>Active Lab Workstations</strong></p>
    
    <div class="card-grid">
        <div class="card">
            <div>Total Active PCs</div>
            <div class="card-val">{total_pcs}</div>
        </div>
        <div class="card">
            <div>Rogue Devices</div>
            <div class="card-val" style="color: {'#f87171' if total_rogues > 0 else '#34d399'}">{total_rogues}</div>
        </div>
        <div class="card">
            <div>Vulnerability Risks</div>
            <div class="card-val" style="color: {'#fbbf24' if total_vulns > 0 else '#34d399'}">{total_vulns}</div>
        </div>
        <div class="card">
            <div>Monitored Labs</div>
            <div class="card-val">{len(labs_breakdown)}</div>
        </div>
    </div>

    <h2>Lab Breakdown</h2>
    <table>
        <tr><th>Lab / Subnet</th><th>Active Endpoints</th></tr>
"""
    for lab, count in labs_breakdown.items():
        html_content += f"<tr><td><strong>{lab}</strong></td><td>{count} PCs</td></tr>"

    html_content += """
    </table>

    <h2>Active Endpoints Matrix</h2>
    <table>
        <tr><th>IP Address</th><th>Computer Name</th><th>Lab</th><th>MAC Address</th><th>Vendor</th><th>Open Services</th></tr>
"""
    for ep in endpoints_raw:
        m = ep.get("metric", {})
        html_content += f"<tr><td><code>{m.get('target_ip', '-')}</code></td><td>{m.get('hostname', '-')}</td><td>{m.get('lab_name', '-')}</td><td><code>{m.get('mac', '-')}</code></td><td>{m.get('vendor', '-')}</td><td>{m.get('open_services', '-')}</td></tr>"

    html_content += """
    </table>
</body>
</html>"""

    with open(REPORT_HTML_PATH, "w", encoding="utf-8") as f:
        f.write(html_content)

    print(f"[SUCCESS] Audit Report Generated!")
    print(f" -> Markdown: {REPORT_MD_PATH}")
    print(f" -> HTML Web: {REPORT_HTML_PATH}")
    print("=" * 70)

if __name__ == "__main__":
    generate_report()
