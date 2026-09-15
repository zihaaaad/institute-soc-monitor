"""Executive SOC audit report (Markdown + self-contained HTML) from live Prometheus data.

Exit codes: 0 = report built from fresh data, 1 = data is stale, 2 = no data
(Prometheus unreachable or monitor not running). A report never claims a
healthy posture it could not measure.
"""
from __future__ import annotations

import base64
import hashlib
import html
import json
import logging
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable

from config_loader import BASE_DIR, ConfigError, load_config
from threat_intel import EXPOSURE_CATALOG, SEVERITY_ORDER

REPORT_MD_PATH = os.path.join(BASE_DIR, "EXECUTIVE_AUDIT_REPORT.md")
REPORT_HTML_PATH = os.path.join(BASE_DIR, "executive_audit_report.html")

STATUS_OK, STATUS_STALE, STATUS_NO_DATA = "OK", "STALE", "NO DATA"

log = logging.getLogger("monitro.report")

Fetcher = Callable[[str], list[dict[str, Any]] | None]


def prometheus_fetcher(base_url: str, timeout: float = 5.0) -> Fetcher:
    def fetch(query: str) -> list[dict[str, Any]] | None:
        url = f"{base_url.rstrip('/')}/api/v1/query?query={urllib.parse.quote(query)}"
        try:
            with urllib.request.urlopen(url, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, OSError, ValueError) as e:
            log.error("Prometheus query failed (%s): %s", query, e)
            return None
        if data.get("status") != "success":
            log.error("Prometheus returned %s for %s", data.get("status"), query)
            return None
        return data.get("data", {}).get("result", [])
    return fetch


@dataclass
class ReportData:
    generated_at: str
    status: str
    status_detail: str
    last_scan_age_seconds: float | None = None
    compliance_percent: float | None = None
    hosts: list[dict[str, Any]] = field(default_factory=list)
    exposures: list[dict[str, str]] = field(default_factory=list)
    detections: list[dict[str, str]] = field(default_factory=list)
    labs: dict[str, int] = field(default_factory=dict)

    @property
    def rogue_count(self) -> int:
        return sum(1 for h in self.hosts if h["asset_status"] == "rogue")

    @property
    def unverified_count(self) -> int:
        return sum(1 for h in self.hosts if h["asset_status"] == "unverified")

    @property
    def material_exposures(self) -> list[dict[str, str]]:
        return [e for e in self.exposures if e["severity"] != "INFO"]


def collect_report_data(fetch: Fetcher, scan_interval: int, now: float | None = None) -> ReportData:
    now = time.time() if now is None else now
    generated = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now))

    heartbeat = fetch("monitor_last_scan_timestamp_seconds")
    if heartbeat is None:
        return ReportData(generated, STATUS_NO_DATA, "Prometheus is unreachable. Start the monitoring stack (start.bat) and retry.")
    if not heartbeat:
        return ReportData(generated, STATUS_NO_DATA, "The monitor has not reported a completed sweep to Prometheus yet.")

    age = now - float(heartbeat[0]["value"][1])
    status, detail = STATUS_OK, "Data from the most recent completed sweep."
    if age > max(3 * scan_interval, 300):
        status, detail = STATUS_STALE, f"Last sweep finished {int(age // 60)} minutes ago; the monitor may be stopped. Figures below are out of date."

    risk_by_ip = {r["metric"].get("target_ip"): float(r["value"][1]) for r in (fetch("endpoint_risk_score") or [])}
    data = ReportData(generated, status, detail, last_scan_age_seconds=age)

    seen: set[str] = set()
    for row in fetch("endpoint_status") or []:
        m = row["metric"]
        ip = m.get("target_ip", "")
        if not ip or ip in seen:
            continue
        seen.add(ip)
        data.hosts.append({
            "ip": ip, "hostname": m.get("hostname", ""), "lab": m.get("lab_name", ""), "subnet": m.get("subnet", ""),
            "mac": m.get("mac", ""), "vendor": m.get("vendor", ""), "services": m.get("open_services", ""),
            "asset_status": m.get("asset_status", "unknown"), "risk": risk_by_ip.get(ip, 0.0),
        })
        data.labs[m.get("lab_name", "")] = data.labs.get(m.get("lab_name", ""), 0) + 1
    data.hosts.sort(key=lambda h: (-h["risk"], tuple(int(o) for o in h["ip"].split(".") if o.isdigit())))

    for row in fetch("vulnerability_exposure") or []:
        m = row["metric"]
        info = EXPOSURE_CATALOG.get(m.get("cve_id", ""), {})
        data.exposures.append({"ip": m.get("target_ip", ""), "id": m.get("cve_id", ""), "severity": m.get("severity", ""),
                               "title": m.get("description", ""), "remediation": str(info.get("remediation", ""))})
    data.exposures.sort(key=lambda e: (-SEVERITY_ORDER.get(e["severity"], 0), e["ip"]))

    for row in fetch('mitre_attack_technique{evidence="detection"}') or []:
        m = row["metric"]
        data.detections.append({"ip": m.get("target_ip", ""), "technique_id": m.get("technique_id", ""),
                                "technique_name": m.get("technique_name", ""), "tactic": m.get("tactic", ""),
                                "severity": m.get("severity", "")})
    data.detections.sort(key=lambda d: (-SEVERITY_ORDER.get(d["severity"], 0), d["ip"]))

    health = fetch("network_health_index") or []
    if health:
        data.compliance_percent = round(float(health[0]["value"][1]), 1)
    return data


def posture_label(data: ReportData) -> str:
    if data.status == STATUS_NO_DATA or data.compliance_percent is None:
        return "NOT MEASURED"
    if data.detections or data.rogue_count:
        return "ACTIVE THREATS - ACTION REQUIRED"
    if data.compliance_percent >= 90:
        return "GOOD"
    if data.compliance_percent >= 70:
        return "ELEVATED RISK"
    return "CRITICAL ATTENTION REQUIRED"


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------
def md(value: Any) -> str:
    """Escape a value for a Markdown table cell."""
    text = str(value if value is not None else "")
    for ch in ("\\", "|", "`", "*", "_", "[", "]", "<", ">"):
        text = text.replace(ch, "\\" + ch)
    return text.replace("\r", " ").replace("\n", " ")


REMEDIATION_CHECKLIST = [
    ("Rogue hardware isolation", "Locate unauthorized MACs via switch CAM tables, shut the port, and review 802.1X/NAC coverage."),
    ("SMBv1 removal", "Disable SMBv1 on every host flagged SMBV1-ENABLED and confirm MS17-010 patch level."),
    ("Remote access boundaries", "Restrict RDP/VNC/WinRM to a management subnet with host firewall rules; require NLA."),
    ("Cleartext protocols", "Retire Telnet/FTP and move web management interfaces to HTTPS."),
    ("Authentication monitoring", "Investigate BRUTE-FORCE/PASSWORD-SPRAY detections: source IPs, targeted accounts, lockout policy."),
    ("Unverified segments", "Deploy a sensor inside routed VLANs or integrate DHCP/switch data so device identity can be verified."),
]


def render_markdown(data: ReportData) -> str:
    out = [
        "# Monitro SOC Security Audit Report", "",
        f"* **Generated:** {md(data.generated_at)}",
        f"* **Data status:** {data.status} - {md(data.status_detail)}",
        f"* **Security posture:** {posture_label(data)}"
        + (f" ({data.compliance_percent}% of hosts compliant)" if data.compliance_percent is not None else ""),
        "",
    ]
    if data.status == STATUS_NO_DATA:
        out += ["> No measurements were available. This report does not represent the security state of the network.", ""]
        return "\n".join(out)

    section = 0

    def heading(title: str) -> None:
        nonlocal section
        section += 1
        out.extend(["---", "", f"## {section}. {title}", ""])

    heading("Executive summary")
    out += ["| Metric | Value |", "| :--- | :--- |",
            f"| Live hosts | {len(data.hosts)} |",
            f"| Rogue / unauthorized devices | {data.rogue_count} |",
            f"| Unverified devices (routed, MAC not visible) | {data.unverified_count} |",
            f"| Exposure findings (LOW+) | {len(data.material_exposures)} |",
            f"| Active ATT&CK detections | {len(data.detections)} |",
            f"| Monitored segments with live hosts | {len(data.labs)} |", ""]

    if data.detections:
        heading("Active threat detections (triage first)")
        out += ["| Host | Severity | Technique | Tactic |", "| :--- | :--- | :--- | :--- |"]
        out += [f"| {md(d['ip'])} | {md(d['severity'])} | {md(d['technique_id'])} {md(d['technique_name'])} | {md(d['tactic'])} |" for d in data.detections]
        out.append("")

    rogues = [h for h in data.hosts if h["asset_status"] == "rogue"]
    if rogues:
        heading("Rogue and unauthorized devices")
        out += ["| IP | MAC | Vendor | Hostname | Segment |", "| :--- | :--- | :--- | :--- | :--- |"]
        out += [f"| {md(h['ip'])} | {md(h['mac'])} | {md(h['vendor'])} | {md(h['hostname'])} | {md(h['lab'])} |" for h in rogues]
        out.append("")

    if data.material_exposures:
        heading("Exposure findings")
        out += ["| Host | Finding | Severity | Remediation |", "| :--- | :--- | :--- | :--- |"]
        out += [f"| {md(e['ip'])} | {md(e['id'])}: {md(e['title'])} | {md(e['severity'])} | {md(e['remediation'])} |" for e in data.material_exposures]
        out.append("")

    heading("Segment distribution")
    out += ["| Segment | Live hosts | Share |", "| :--- | :--- | :--- |"]
    for lab, count in sorted(data.labs.items(), key=lambda kv: -kv[1]):
        out.append(f"| {md(lab)} | {count} | {round(100 * count / len(data.hosts), 1) if data.hosts else 0}% |")
    out.append("")

    heading("Endpoint inventory")
    out += ["| IP | Hostname | Segment | MAC | Vendor | Services | Asset | Risk |",
            "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |"]
    out += [f"| {md(h['ip'])} | {md(h['hostname'])} | {md(h['lab'])} | {md(h['mac'])} | {md(h['vendor'])} | {md(h['services'])} | {md(h['asset_status'])} | {h['risk']:.0f} |"
            for h in data.hosts]
    out.append("")

    heading("Remediation checklist")
    out += [f"{i}. **{title}**: {text}" for i, (title, text) in enumerate(REMEDIATION_CHECKLIST, 1)]
    out += ["", "---", "*Generated by Monitro. Risk scores are analyst-weighted, not CVSS base scores.*", ""]
    return "\n".join(out)


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------
REPORT_CSS = """
:root{--bg:#f8fafc;--card:#fff;--line:#e2e8f0;--text:#0f172a;--muted:#64748b;--primary:#0284c7;
--ok-bg:#ecfdf5;--ok:#065f46;--ok-line:#a7f3d0;--bad-bg:#fef2f2;--bad:#991b1b;--bad-line:#fecaca;--warn-bg:#fffbeb;--warn:#92400e;--warn-line:#fde68a}
*{box-sizing:border-box;margin:0;padding:0}body{background:var(--bg);color:var(--text);font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif;padding:30px}
.container{max-width:1280px;margin:0 auto}.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:22px;margin-bottom:20px}
.header{display:flex;justify-content:space-between;align-items:center;gap:16px}h1{font-size:22px}h2{font-size:16px;margin-bottom:14px}.meta{color:var(--muted);font-size:13px}
button{background:var(--primary);color:#fff;border:0;padding:9px 16px;border-radius:8px;font-weight:600;cursor:pointer}
.banner{border-radius:10px;padding:14px 18px;margin-bottom:20px;font-weight:600}.banner.OK{background:var(--ok-bg);color:var(--ok);border:1px solid var(--ok-line)}
.banner.STALE{background:var(--warn-bg);color:var(--warn);border:1px solid var(--warn-line)}.banner.NODATA{background:var(--bad-bg);color:var(--bad);border:1px solid var(--bad-line)}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:14px;margin-bottom:20px}.kpi{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px}
.kpi .label{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}.kpi .value{font-size:26px;font-weight:700}
.badge{display:inline-block;padding:2px 8px;border-radius:6px;font-size:12px;font-weight:600;border:1px solid transparent}
.CRITICAL,.HIGH,.rogue{background:var(--bad-bg);color:var(--bad);border-color:var(--bad-line)}.MEDIUM,.unverified,.unmanaged{background:var(--warn-bg);color:var(--warn);border-color:var(--warn-line)}
.LOW,.INFO{background:#f0f9ff;color:#0369a1;border-color:#bae6fd}.authorized{background:var(--ok-bg);color:var(--ok);border-color:var(--ok-line)}
.controls{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:12px}.controls input{flex:1;min-width:240px;padding:8px 12px;border:1px solid var(--line);border-radius:8px}
.filter{background:#fff;color:var(--muted);border:1px solid var(--line);font-size:12px;padding:7px 12px}.filter.active{background:var(--primary);color:#fff;border-color:var(--primary)}
.wrap{overflow-x:auto;border:1px solid var(--line);border-radius:8px}table{width:100%;border-collapse:collapse;font-size:13px}
th{background:#f1f5f9;text-align:left;padding:10px 12px;border-bottom:1px solid var(--line);cursor:pointer;user-select:none}td{padding:10px 12px;border-bottom:1px solid var(--line)}
code{font:12px ui-monospace,Consolas,monospace;background:#f1f5f9;padding:1px 5px;border-radius:4px}.bar{height:8px;background:#e2e8f0;border-radius:99px;overflow:hidden;margin-top:6px}
.bar div{height:100%;background:var(--primary)}.labs{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px}.lab{border:1px solid var(--line);border-radius:8px;padding:12px}
ol.check li{margin:0 0 8px 20px}[hidden]{display:none!important}
@media print{body{padding:0;background:#fff}.controls,button{display:none}.card{break-inside:avoid}}
"""

REPORT_JS = """
(function(){
  var filter='all';
  var rows=Array.prototype.slice.call(document.querySelectorAll('#inventory tbody tr'));
  var search=document.getElementById('search');
  function apply(){
    var q=search.value.trim().toLowerCase(), shown=0;
    rows.forEach(function(r){
      var ok=(!q||r.textContent.toLowerCase().indexOf(q)!==-1)&&(filter==='all'||(filter==='rogue'&&r.dataset.asset==='rogue')||(filter==='exposed'&&r.dataset.exposed==='1'));
      r.hidden=!ok; if(ok){shown++;}
    });
    document.getElementById('shown').textContent=shown+' of '+rows.length+' hosts shown';
  }
  search.addEventListener('input',apply);
  Array.prototype.forEach.call(document.querySelectorAll('.filter'),function(b){
    b.addEventListener('click',function(){
      filter=b.dataset.filter;
      Array.prototype.forEach.call(document.querySelectorAll('.filter'),function(x){x.classList.toggle('active',x===b);});
      apply();
    });
  });
  Array.prototype.forEach.call(document.querySelectorAll('#inventory th'),function(th,idx){
    th.addEventListener('click',function(){
      var asc=th.dataset.dir!=='asc'; th.dataset.dir=asc?'asc':'desc';
      var body=document.querySelector('#inventory tbody');
      rows.sort(function(a,b){var x=a.cells[idx].textContent.trim(),y=b.cells[idx].textContent.trim();return asc?x.localeCompare(y,undefined,{numeric:true}):y.localeCompare(x,undefined,{numeric:true});});
      rows.forEach(function(r){body.appendChild(r);});
    });
  });
  document.getElementById('print').addEventListener('click',function(){window.print();});
  Array.prototype.forEach.call(document.querySelectorAll('.bar div'),function(d){d.style.width=d.dataset.pct+'%';});
  apply();
})();
"""


def _csp_hash(content: str) -> str:
    return "'sha256-" + base64.b64encode(hashlib.sha256(content.encode("utf-8")).digest()).decode() + "'"


def e(value: Any) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def render_html(data: ReportData) -> str:
    csp = f"default-src 'none'; style-src {_csp_hash(REPORT_CSS)}; script-src {_csp_hash(REPORT_JS)}; base-uri 'none'; form-action 'none'"
    banner_class = data.status.replace(" ", "")
    exposed_ips = {x["ip"] for x in data.material_exposures}
    parts = [
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">",
        f"<meta http-equiv=\"Content-Security-Policy\" content=\"{e(csp)}\">",
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
        "<title>Monitro SOC Security Audit Report</title>",
        f"<style>{REPORT_CSS}</style></head><body><div class=\"container\">",
        "<div class=\"card header\"><div><h1>Monitro SOC Security Audit Report</h1>",
        f"<div class=\"meta\">Generated {e(data.generated_at)}</div></div><button id=\"print\" type=\"button\">Print / Save as PDF</button></div>",
        f"<div class=\"banner {e(banner_class)}\">Data status: {e(data.status)} - {e(data.status_detail)}</div>",
    ]

    if data.status == STATUS_NO_DATA:
        parts.append("<div class=\"card\"><h2>No measurements available</h2><p>This report does not represent the security state of the network.</p></div>")
        parts.append("</div></body></html>")
        return "".join(parts)

    compliance = f"{data.compliance_percent}%" if data.compliance_percent is not None else "n/a"
    kpis = [
        ("Security posture", posture_label(data)), ("Compliant hosts", compliance), ("Live hosts", len(data.hosts)),
        ("Rogue devices", data.rogue_count), ("Unverified devices", data.unverified_count),
        ("Exposures (LOW+)", len(data.material_exposures)), ("Active detections", len(data.detections)),
    ]
    parts.append("<div class=\"kpis\">" + "".join(
        f"<div class=\"kpi\"><div class=\"label\">{e(k)}</div><div class=\"value\">{e(v)}</div></div>" for k, v in kpis) + "</div>")

    if data.detections:
        parts.append("<div class=\"card\"><h2>Active threat detections (triage first)</h2><div class=\"wrap\"><table><thead><tr><th>Host</th><th>Severity</th><th>Technique</th><th>Tactic</th></tr></thead><tbody>")
        parts += [f"<tr><td><code>{e(d['ip'])}</code></td><td><span class=\"badge {e(d['severity'])}\">{e(d['severity'])}</span></td>"
                  f"<td>{e(d['technique_id'])} {e(d['technique_name'])}</td><td>{e(d['tactic'])}</td></tr>" for d in data.detections]
        parts.append("</tbody></table></div></div>")

    if data.material_exposures:
        parts.append("<div class=\"card\"><h2>Exposure findings</h2><div class=\"wrap\"><table><thead><tr><th>Host</th><th>Finding</th><th>Severity</th><th>Remediation</th></tr></thead><tbody>")
        parts += [f"<tr><td><code>{e(x['ip'])}</code></td><td><strong>{e(x['id'])}</strong><br>{e(x['title'])}</td>"
                  f"<td><span class=\"badge {e(x['severity'])}\">{e(x['severity'])}</span></td><td>{e(x['remediation'])}</td></tr>" for x in data.material_exposures]
        parts.append("</tbody></table></div></div>")

    parts.append("<div class=\"card\"><h2>Segment distribution</h2><div class=\"labs\">")
    for lab, count in sorted(data.labs.items(), key=lambda kv: -kv[1]):
        pct = round(100 * count / len(data.hosts), 1) if data.hosts else 0
        parts.append(f"<div class=\"lab\"><strong>{e(lab)}</strong> - {count} hosts ({pct}%)<div class=\"bar\"><div data-pct=\"{pct}\"></div></div></div>")
    parts.append("</div></div>")

    parts.append("<div class=\"card\"><h2>Endpoint inventory</h2><div class=\"controls\">"
                 "<input id=\"search\" type=\"search\" placeholder=\"Search IP, hostname, segment, MAC, vendor\">"
                 "<button class=\"filter active\" data-filter=\"all\" type=\"button\">All</button>"
                 "<button class=\"filter\" data-filter=\"rogue\" type=\"button\">Rogue only</button>"
                 "<button class=\"filter\" data-filter=\"exposed\" type=\"button\">With exposures</button>"
                 "<span id=\"shown\" class=\"meta\"></span></div>"
                 "<div class=\"wrap\"><table id=\"inventory\"><thead><tr><th>IP</th><th>Hostname</th><th>Segment</th><th>MAC</th><th>Vendor</th><th>Services</th><th>Asset</th><th>Risk</th></tr></thead><tbody>")
    for h in data.hosts:
        parts.append(
            f"<tr data-asset=\"{e(h['asset_status'])}\" data-exposed=\"{1 if h['ip'] in exposed_ips else 0}\">"
            f"<td><code>{e(h['ip'])}</code></td><td>{e(h['hostname'])}</td><td>{e(h['lab'])}</td><td><code>{e(h['mac'])}</code></td>"
            f"<td>{e(h['vendor'])}</td><td>{e(h['services'])}</td><td><span class=\"badge {e(h['asset_status'])}\">{e(h['asset_status'])}</span></td>"
            f"<td>{h['risk']:.0f}</td></tr>")
    parts.append("</tbody></table></div></div>")

    parts.append("<div class=\"card\"><h2>Remediation checklist</h2><ol class=\"check\">")
    parts += [f"<li><strong>{e(t)}</strong>: {e(d)}</li>" for t, d in REMEDIATION_CHECKLIST]
    parts.append("</ol><p class=\"meta\">Risk scores are analyst-weighted, not CVSS base scores.</p></div>")
    parts.append(f"</div><script>{REPORT_JS}</script></body></html>")
    return "".join(parts)


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    try:
        config = load_config()
    except ConfigError as err:
        log.critical("Configuration error: %s", err)
        return 2

    data = collect_report_data(prometheus_fetcher(config["settings"]["prometheus_url"]), config["settings"]["scan_interval_seconds"])
    with open(REPORT_MD_PATH, "w", encoding="utf-8") as f:
        f.write(render_markdown(data))
    with open(REPORT_HTML_PATH, "w", encoding="utf-8") as f:
        f.write(render_html(data))

    print(f"Report status: {data.status} - {data.status_detail}")
    print(f"  Markdown: {REPORT_MD_PATH}")
    print(f"  HTML:     {REPORT_HTML_PATH}")
    return {STATUS_OK: 0, STATUS_STALE: 1}.get(data.status, 2)


if __name__ == "__main__":
    sys.exit(main())
