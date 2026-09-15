"""Monitro agentless network security monitor (Prometheus exporter).

Usage:
  python src\\agentless_monitor_win.py                    run continuously
  python src\\agentless_monitor_win.py --once             one sweep, print JSON summary
  python src\\agentless_monitor_win.py --export-baseline  one sweep, write asset_baseline.json for review
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import logging.handlers
import os
import sys
import time

from prometheus_client import start_http_server
from prometheus_client.core import REGISTRY

from alerting import AlertDispatcher
from config_loader import BASE_DIR, LOG_DIR, ConfigError, load_config
from engine import SweepEngine, build_host_views, summarize
from metrics_collector import SocCollector
from wmi_audit import WmiAuditor

log = logging.getLogger("monitro")
BASELINE_PATH = os.path.join(BASE_DIR, "asset_baseline.json")


def setup_logging(level: str) -> None:
    os.makedirs(LOG_DIR, exist_ok=True)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    console = logging.StreamHandler()
    console.setFormatter(fmt)
    file_handler = logging.handlers.RotatingFileHandler(
        os.path.join(LOG_DIR, "monitor.log"), maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8")
    file_handler.setFormatter(fmt)
    root.handlers = [console, file_handler]


def export_baseline(engine: SweepEngine, path: str = BASELINE_PATH) -> int:
    snapshot = engine.run_cycle()
    devices = sorted(
        ({"mac": h.mac, "ip": h.ip, "hostname": h.hostname, "vendor": h.vendor, "lab_name": h.lab_name}
         for h in snapshot.hosts.values() if h.mac),
        key=lambda d: d["ip"])
    payload = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "note": "REVIEW EVERY ENTRY before trusting it: a rogue device present today would be whitelisted. "
                "Only devices on subnets local to this sensor have visible MACs.",
        "devices": devices,
        "asset_whitelist": sorted({d["mac"] for d in devices}),
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    print(f"Wrote {len(devices)} devices with visible MACs to {path}")
    print("After review, copy the 'asset_whitelist' array into config.local.json.")
    return 0


def run_forever(config: dict, engine: SweepEngine, auditor: WmiAuditor) -> int:
    settings = config["settings"]
    bind = settings["metrics_bind_address"]
    port = settings["metrics_port"]
    REGISTRY.register(SocCollector(engine, auditor))
    try:
        start_http_server(port, addr=bind)
    except OSError as e:
        log.critical("Cannot bind metrics endpoint %s:%d (%s). Is another instance running?", bind, port, e)
        return 1
    log.info("Metrics exporter listening on http://%s:%d/metrics", bind, port)
    try:
        if not ipaddress.ip_address(bind).is_loopback:
            log.warning("SECURITY: metrics are exposed on %s. They contain a full network inventory and exposure "
                        "map and have no authentication; restrict with a host firewall.", bind)
    except ValueError:
        pass

    interval = settings["scan_interval_seconds"]
    while True:
        started = time.monotonic()
        try:
            snapshot = engine.run_cycle()
            views = build_host_views(snapshot, {}, time.time(), 0)
            auditor.submit(views)
            if snapshot.duration > interval:
                log.warning("Sweep took %.0fs, longer than scan_interval_seconds=%d. Reduce subnets or raise the interval.",
                            snapshot.duration, interval)
        except Exception:
            log.exception("Sweep cycle failed; retrying next interval")
        time.sleep(max(1.0, interval - (time.monotonic() - started)))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Monitro agentless network security monitor")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--once", action="store_true", help="run a single sweep and print a JSON summary")
    mode.add_argument("--export-baseline", action="store_true", help="run a sweep and write asset_baseline.json")
    parser.add_argument("--log-level", default="INFO")
    args = parser.parse_args(argv)

    setup_logging(args.log_level)
    try:
        config = load_config()
    except ConfigError as e:
        log.critical("Configuration error: %s", e)
        return 2

    dispatcher = AlertDispatcher(config["alerts"])
    engine = SweepEngine(config, alert_sink=dispatcher.dispatch)
    auditor = WmiAuditor(config, alert_sink=dispatcher.dispatch)

    try:
        if args.export_baseline:
            return export_baseline(engine)
        if args.once:
            snapshot = engine.run_cycle()
            views = build_host_views(snapshot, {}, time.time(), 0)
            print(json.dumps({"duration_seconds": snapshot.duration, **summarize(views)}, indent=2))
            return 0
        return run_forever(config, engine, auditor)
    except KeyboardInterrupt:
        log.info("Stopped by user")
        return 0
    finally:
        auditor.shutdown()


if __name__ == "__main__":
    sys.exit(main())
