"""Standalone SOC web console (alternative to the Prometheus + Grafana stack).

Run *instead of* agentless_monitor_win.py, not alongside it, or the network is
swept twice.

Security model:
* Binds to 127.0.0.1 by default. Binding to any other address requires
  dashboard credentials (MONITRO_DASHBOARD_USER / MONITRO_DASHBOARD_PASSWORD);
  the process refuses to start otherwise.
* HTTP Basic auth compared in constant time. Use a TLS reverse proxy for
  remote access; Basic credentials are only base64-encoded.
* State-changing POST requires a custom header, which browsers will not send
  cross-origin without a CORS preflight (no CORS is enabled), blocking CSRF.
* Strict Content-Security-Policy, no third-party CDNs, and the UI renders all
  data with textContent (hostnames are attacker-controlled).

No `from __future__ import annotations` here: FastAPI must evaluate the
Annotated[..., Depends(...)] hints at definition time, otherwise the auth
dependency silently degrades into a query parameter.
"""
import ipaddress
import logging
import secrets
import sys
import threading
import time
from contextlib import asynccontextmanager
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.responses import HTMLResponse, Response
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel

from alerting import AlertDispatcher
from config_loader import ConfigError, load_config
from engine import SweepEngine, build_host_views, summarize
from wmi_audit import WmiAuditor

log = logging.getLogger("monitro.dashboard")

CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; "
       "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
CSRF_HEADER_VALUE = "1"


class Summary(BaseModel):
    total_hosts: int
    rogue: int
    unverified: int
    exposures: int
    threat_hosts: int
    compliance_percent: float | None
    is_scanning: bool
    last_scan: str | None
    scan_duration_seconds: float | None
    labs: dict[str, int]


class Finding(BaseModel):
    id: str
    title: str
    severity: str
    technique_id: str


class Host(BaseModel):
    ip: str
    hostname: str
    lab_name: str
    mac: str | None
    vendor: str
    services: list[str]
    asset_status: str
    risk_score: float
    compliant: bool
    wmi_status: str
    exposures: list[Finding]
    detections: list[Finding]


class Alert(BaseModel):
    timestamp: str
    severity: str
    title: str
    target_ip: str
    message: str


class ScanStatus(BaseModel):
    status: str


def is_loopback(address: str) -> bool:
    try:
        return ipaddress.ip_address(address).is_loopback
    except ValueError:
        return address == "localhost"


def create_app(config: dict[str, Any], engine: Any, auditor: Any, dispatcher: Any, run_background: bool = True) -> FastAPI:
    dash = config.get("dashboard", {})
    username = str(dash.get("username") or "")
    password = str(dash.get("password") or "")
    interval = config["settings"]["scan_interval_seconds"]
    stale_after = max(3 * interval, 600)
    stop = threading.Event()

    def scan_loop() -> None:
        while not stop.is_set():
            started = time.monotonic()
            try:
                snapshot = engine.try_run_cycle()
                if snapshot is not None:
                    auditor.submit(build_host_views(snapshot, {}, time.time(), 0))
            except Exception:
                log.exception("Sweep cycle failed")
            stop.wait(max(1.0, interval - (time.monotonic() - started)))

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        if run_background:
            threading.Thread(target=scan_loop, name="scan-loop", daemon=True).start()
        yield
        stop.set()

    basic = HTTPBasic(auto_error=False)

    def require_user(credentials: Annotated[HTTPBasicCredentials | None, Depends(basic)]) -> None:
        if not username and not password:
            return  # only reachable when bound to loopback (enforced in main)
        ok = credentials is not None and secrets.compare_digest(credentials.username.encode(), username.encode()) \
            and secrets.compare_digest(credentials.password.encode(), password.encode())
        if not ok:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Authentication required",
                                headers={"WWW-Authenticate": 'Basic realm="Monitro"'})

    UserDep = Depends(require_user)
    app = FastAPI(title="Monitro SOC Console", lifespan=lifespan, dependencies=[UserDep],
                  docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    def current_views() -> list[dict[str, Any]]:
        return build_host_views(engine.latest(), auditor.results(), time.time(), stale_after)

    @app.get("/api/summary")
    def get_summary() -> Summary:
        snapshot = engine.latest()
        views = current_views()
        labs: dict[str, int] = {lab: 0 for lab in engine.subnets.values()}
        for v in views:
            labs[v["lab_name"]] = labs.get(v["lab_name"], 0) + 1
        return Summary(
            **summarize(views),
            is_scanning=engine.is_scanning,
            last_scan=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(snapshot.finished_at)) if snapshot else None,
            scan_duration_seconds=snapshot.duration if snapshot else None,
            labs=labs,
        )

    @app.get("/api/hosts")
    def get_hosts() -> list[Host]:
        return [
            Host(
                ip=v["ip"], hostname=v["hostname"], lab_name=v["lab_name"], mac=v["mac"], vendor=v["vendor"],
                services=v["services"], asset_status=v["asset_status"], risk_score=v["risk_score"],
                compliant=v["compliant"], wmi_status=v["wmi_status"],
                exposures=[Finding(id=e["id"], title=str(e["title"]), severity=str(e["severity"]), technique_id=str(e["technique_id"]))
                           for e in v["exposure_records"]],
                detections=[Finding(id=str(d["id"]), title=str(d["title"]), severity=str(d["severity"]), technique_id=str(d["technique_id"]))
                            for d in v["detections"]],
            )
            for v in current_views()
        ]

    @app.get("/api/alerts")
    def get_alerts() -> list[Alert]:
        return [Alert(**{k: e[k] for k in Alert.model_fields}) for e in list(dispatcher.recent)]

    @app.post("/api/scan-now", status_code=status.HTTP_202_ACCEPTED)
    def scan_now(x_monitro_request: Annotated[str | None, Header()] = None) -> ScanStatus:
        if x_monitro_request != CSRF_HEADER_VALUE:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Missing X-Monitro-Request header")
        if engine.is_scanning:
            raise HTTPException(status.HTTP_409_CONFLICT, "A sweep is already running")
        threading.Thread(target=engine.try_run_cycle, name="manual-scan", daemon=True).start()
        return ScanStatus(status="started")

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return INDEX_HTML

    @app.get("/static/app.js")
    def app_js() -> Response:
        return Response(APP_JS, media_type="application/javascript")

    @app.get("/static/app.css")
    def app_css() -> Response:
        return Response(APP_CSS, media_type="text/css")

    return app


INDEX_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Monitro SOC Console</title>
<link rel="stylesheet" href="/static/app.css">
<script src="/static/app.js" defer></script>
</head>
<body>
<header>
  <div><h1>Monitro SOC Console</h1><p id="meta">Waiting for first sweep...</p></div>
  <button id="scan" type="button">Scan now</button>
</header>
<main>
  <section class="kpis">
    <div class="kpi"><span>Live hosts</span><strong id="k-hosts">-</strong></div>
    <div class="kpi"><span>Rogue devices</span><strong id="k-rogue">-</strong></div>
    <div class="kpi"><span>Unverified (routed)</span><strong id="k-unverified">-</strong></div>
    <div class="kpi"><span>Exposures</span><strong id="k-exposures">-</strong></div>
    <div class="kpi"><span>Hosts with detections</span><strong id="k-threats">-</strong></div>
    <div class="kpi"><span>Compliance</span><strong id="k-compliance">-</strong></div>
  </section>
  <section class="grid">
    <div class="card"><h2>Alerts</h2><ol id="alerts" class="alerts"></ol></div>
    <div class="card wide">
      <div class="row"><h2>Endpoint inventory</h2><input id="search" type="search" placeholder="Filter IP, name, lab, MAC, vendor"></div>
      <div class="scroll"><table>
        <thead><tr><th>IP</th><th>Name</th><th>Lab</th><th>MAC / vendor</th><th>Services</th><th>Asset</th><th>Risk</th><th>Findings</th><th>WMI</th></tr></thead>
        <tbody id="hosts"></tbody>
      </table></div>
    </div>
  </section>
</main>
</body>
</html>"""

APP_CSS = """
:root{--bg:#f8fafc;--card:#fff;--line:#e2e8f0;--text:#0f172a;--muted:#64748b;--accent:#0369a1;--bad:#b91c1c;--warn:#b45309;--ok:#047857}
*{box-sizing:border-box}body{margin:0;font:14px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;background:var(--bg);color:var(--text)}
header{display:flex;justify-content:space-between;align-items:center;gap:16px;padding:16px 24px;background:var(--card);border-bottom:1px solid var(--line)}
h1{font-size:18px;margin:0}h2{font-size:14px;margin:0 0 12px}#meta{margin:2px 0 0;color:var(--muted);font-size:12px}
button{background:var(--accent);color:#fff;border:0;border-radius:6px;padding:8px 14px;font-weight:600;cursor:pointer}button:disabled{opacity:.5;cursor:wait}
main{padding:20px 24px;max-width:1500px;margin:0 auto}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:16px}
.kpi{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 14px}.kpi span{display:block;font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
.kpi strong{font-size:24px}.grid{display:grid;grid-template-columns:minmax(260px,1fr) 3fr;gap:16px}@media(max-width:1000px){.grid{grid-template-columns:1fr}}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:14px;min-width:0}.row{display:flex;justify-content:space-between;gap:12px;align-items:center;margin-bottom:8px}
input{border:1px solid var(--line);border-radius:6px;padding:6px 10px;min-width:220px}.scroll{overflow:auto;max-height:70vh}
table{width:100%;border-collapse:collapse;font-size:12px}th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--line);vertical-align:top}th{position:sticky;top:0;background:#f1f5f9}
code{font:12px ui-monospace,Consolas,monospace}.tag{display:inline-block;border-radius:4px;padding:1px 6px;font-size:11px;font-weight:600;margin:1px;border:1px solid var(--line)}
.CRITICAL,.HIGH,.rogue{color:var(--bad);border-color:#fecaca;background:#fef2f2}.MEDIUM,.unverified,.unmanaged{color:var(--warn);border-color:#fde68a;background:#fffbeb}
.LOW,.INFO{color:var(--accent);border-color:#bae6fd;background:#f0f9ff}.authorized{color:var(--ok);border-color:#a7f3d0;background:#ecfdf5}
.alerts{list-style:none;margin:0;padding:0;max-height:70vh;overflow:auto}.alerts li{border-left:3px solid var(--line);padding:6px 8px;margin-bottom:6px;background:#f8fafc}
.alerts li.HIGH,.alerts li.CRITICAL{border-left-color:var(--bad)}.alerts li.MEDIUM{border-left-color:var(--warn)}.alerts small{color:var(--muted);display:block}
"""

APP_JS = """
'use strict';
let hosts = [];
const $ = (id) => document.getElementById(id);

function el(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined && text !== null) node.textContent = String(text);
  if (className) node.className = className;
  return node;
}

async function getJson(path) {
  const res = await fetch(path, {credentials: 'same-origin', cache: 'no-store'});
  if (!res.ok) throw new Error(path + ' -> ' + res.status);
  return res.json();
}

function renderSummary(s) {
  $('k-hosts').textContent = s.total_hosts;
  $('k-rogue').textContent = s.rogue;
  $('k-unverified').textContent = s.unverified;
  $('k-exposures').textContent = s.exposures;
  $('k-threats').textContent = s.threat_hosts;
  $('k-compliance').textContent = s.compliance_percent === null ? 'no data' : s.compliance_percent + '%';
  $('meta').textContent = s.last_scan
    ? 'Last sweep ' + s.last_scan + ' (' + s.scan_duration_seconds + 's)' + (s.is_scanning ? ' - sweeping now' : '')
    : (s.is_scanning ? 'First sweep in progress...' : 'No sweep yet');
  $('scan').disabled = s.is_scanning;
}

function renderHosts() {
  const q = $('search').value.trim().toLowerCase();
  const body = $('hosts');
  body.replaceChildren();
  for (const h of hosts) {
    const hay = [h.ip, h.hostname, h.lab_name, h.mac, h.vendor, h.asset_status].join(' ').toLowerCase();
    if (q && !hay.includes(q)) continue;
    const tr = document.createElement('tr');
    tr.append(el('td', h.ip), el('td', h.hostname || '(unresolved)'), el('td', h.lab_name));
    const macCell = el('td');
    macCell.append(el('code', h.mac || 'not visible'), el('div', h.vendor));
    tr.append(macCell, el('td', h.services.join(', ') || 'none'));
    const asset = el('td');
    asset.append(el('span', h.asset_status, 'tag ' + h.asset_status));
    tr.append(asset, el('td', h.risk_score));
    const findings = el('td');
    for (const f of h.detections.concat(h.exposures)) {
      const tag = el('span', f.id, 'tag ' + f.severity);
      tag.title = f.title + ' (' + f.technique_id + ')';
      findings.append(tag);
    }
    tr.append(findings, el('td', h.wmi_status));
    body.append(tr);
  }
}

function renderAlerts(alerts) {
  const list = $('alerts');
  list.replaceChildren();
  if (!alerts.length) { list.append(el('li', 'No alerts recorded.')); return; }
  for (const a of alerts) {
    const li = el('li', null, a.severity);
    li.append(el('strong', '[' + a.severity + '] ' + a.title), el('div', a.message), el('small', a.timestamp + ' - ' + a.target_ip));
    list.append(li);
  }
}

async function refresh() {
  try {
    const [summary, hostList, alerts] = await Promise.all([getJson('/api/summary'), getJson('/api/hosts'), getJson('/api/alerts')]);
    hosts = hostList;
    renderSummary(summary);
    renderHosts();
    renderAlerts(alerts);
  } catch (err) {
    $('meta').textContent = 'Console error: ' + err.message;
  }
}

async function scanNow() {
  $('scan').disabled = true;
  await fetch('/api/scan-now', {method: 'POST', credentials: 'same-origin', headers: {'X-Monitro-Request': '1'}});
  setTimeout(refresh, 1000);
}

document.addEventListener('DOMContentLoaded', () => {
  $('search').addEventListener('input', renderHosts);
  $('scan').addEventListener('click', scanNow);
  refresh();
  setInterval(refresh, 5000);
});
"""


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    try:
        config = load_config()
    except ConfigError as e:
        log.critical("Configuration error: %s", e)
        return 2

    dash = config["dashboard"]
    bind = str(dash.get("bind_address") or "127.0.0.1")
    has_credentials = bool(dash.get("username")) and bool(dash.get("password"))
    if not is_loopback(bind) and not has_credentials:
        log.critical("Refusing to bind %s without authentication. Set MONITRO_DASHBOARD_USER and "
                     "MONITRO_DASHBOARD_PASSWORD, or keep bind_address=127.0.0.1.", bind)
        return 2
    if has_credentials and len(str(dash["password"])) < 12:
        log.warning("SECURITY: dashboard password is shorter than 12 characters.")

    import uvicorn

    dispatcher = AlertDispatcher(config["alerts"])
    engine = SweepEngine(config, alert_sink=dispatcher.dispatch)
    auditor = WmiAuditor(config, alert_sink=dispatcher.dispatch)
    app = create_app(config, engine, auditor, dispatcher)
    log.info("Monitro console on http://%s:%d", bind, int(dash.get("port", 5000)))
    try:
        uvicorn.run(app, host=bind, port=int(dash.get("port", 5000)), log_level="warning", server_header=False)
    finally:
        auditor.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
