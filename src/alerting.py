"""Alert dispatch: local JSONL audit trail plus optional Discord / Telegram webhooks.

* Every alert is written to logs/alerts.jsonl (rotated), even when webhooks are
  disabled, so there is always a local record for incident review or SIEM ingest.
* Webhooks run on one worker thread behind a bounded queue: an alert storm
  cannot spawn unbounded threads, and a slow webhook cannot stall scanning.
* Messages leaving the network carry minimal data by default
  (alerts.include_evidence=false keeps command lines and account names local).
"""
from __future__ import annotations

import collections
import json
import logging
import logging.handlers
import os
import queue
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable

from config_loader import LOG_DIR

log = logging.getLogger("monitro.alerts")

SEVERITY_COLORS = {"CRITICAL": 0x991B1B, "HIGH": 0xE74C3C, "MEDIUM": 0xF1C40F, "LOW": 0x3498DB, "INFO": 0x95A5A6}


def _alert_file_handler(log_dir: str) -> logging.Handler:
    os.makedirs(log_dir, exist_ok=True)
    handler = logging.handlers.RotatingFileHandler(
        os.path.join(log_dir, "alerts.jsonl"), maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(message)s"))
    return handler


def is_allowed_webhook(url: str) -> bool:
    parsed = urllib.parse.urlparse(url)
    return parsed.scheme == "https" and bool(parsed.hostname)


class AlertDispatcher:
    def __init__(
        self,
        alerts_config: dict[str, Any],
        log_dir: str = LOG_DIR,
        sender: Callable[[str, dict[str, Any]], None] | None = None,
        clock: Callable[[], float] = time.time,
    ):
        self.config = alerts_config
        self.cooldown = float(alerts_config.get("alert_cooldown_seconds", 900))
        self.include_evidence = bool(alerts_config.get("include_evidence", False))
        self._clock = clock
        self._sender = sender or self._post_json
        self._last_sent: dict[str, float] = {}
        self._lock = threading.Lock()
        self._queue: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=500)
        self.recent: collections.deque[dict[str, Any]] = collections.deque(maxlen=200)
        self._file_handler = _alert_file_handler(log_dir) if log_dir else None
        self._worker: threading.Thread | None = None

        for key in ("discord_webhook_url",):
            url = str(alerts_config.get(key) or "").strip()
            if url and not is_allowed_webhook(url):
                log.error("Ignoring %s: webhooks must use https://", key)
                self.config = {**self.config, key: ""}

    def dispatch(self, title: str, severity: str, target_ip: str, dedup_key: str, message: str, evidence: str = "") -> bool:
        """Record an alert. Returns False when suppressed by the cooldown."""
        now = self._clock()
        key = f"{target_ip}|{dedup_key}"
        with self._lock:
            last = self._last_sent.get(key)
            if last is not None and now - last < self.cooldown:
                return False
            self._last_sent[key] = now
            if len(self._last_sent) > 10_000:
                cutoff = now - self.cooldown
                self._last_sent = {k: v for k, v in self._last_sent.items() if v >= cutoff}

        event = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(now)),
            "severity": severity.upper(),
            "title": title,
            "target_ip": target_ip,
            "type": dedup_key,
            "message": message,
            "evidence": evidence,
        }
        self.recent.appendleft(event)
        if self._file_handler:
            self._file_handler.emit(logging.makeLogRecord({"msg": json.dumps(event, ensure_ascii=False), "levelno": logging.INFO}))
        log.warning("[ALERT][%s] %s - %s (%s)", event["severity"], title, message, target_ip)

        if self.config.get("enabled"):
            self._ensure_worker()
            try:
                self._queue.put_nowait(event)
            except queue.Full:
                log.error("Alert queue full; webhook delivery dropped for %s", key)
        return True

    def close(self) -> None:
        if self._file_handler:
            self._file_handler.close()

    # ------------------------------------------------------------------
    def _ensure_worker(self) -> None:
        if self._worker is None or not self._worker.is_alive():
            self._worker = threading.Thread(target=self._run, name="alert-dispatcher", daemon=True)
            self._worker.start()

    def _run(self) -> None:
        while True:
            event = self._queue.get()
            try:
                self.deliver(event)
            except Exception:  # never let one bad alert kill the worker
                log.exception("Unexpected error delivering alert")
            finally:
                self._queue.task_done()

    def build_discord_payload(self, event: dict[str, Any]) -> dict[str, Any]:
        description = event["message"]
        if self.include_evidence and event.get("evidence"):
            description += f"\nEvidence: {event['evidence']}"
        return {
            "username": "Monitro SOC",
            "allowed_mentions": {"parse": []},  # hostnames must not be able to ping @everyone
            "embeds": [{
                "title": f"[{event['severity']}] {event['title']}"[:256],
                "description": description[:3500],
                "color": SEVERITY_COLORS.get(event["severity"], 0x95A5A6),
                "fields": [
                    {"name": "Target", "value": event["target_ip"][:100] or "-", "inline": True},
                    {"name": "Time", "value": event["timestamp"], "inline": True},
                ],
            }],
        }

    def build_telegram_text(self, event: dict[str, Any]) -> str:
        text = f"[{event['severity']}] {event['title']}\n{event['message']}\nTarget: {event['target_ip']}\nTime: {event['timestamp']}"
        if self.include_evidence and event.get("evidence"):
            text += f"\nEvidence: {event['evidence']}"
        return text[:4000]

    def deliver(self, event: dict[str, Any]) -> None:
        discord_url = str(self.config.get("discord_webhook_url") or "").strip()
        if discord_url:
            self._safe_send("Discord", discord_url, self.build_discord_payload(event))

        token = str(self.config.get("telegram_bot_token") or "").strip()
        chat_id = str(self.config.get("telegram_chat_id") or "").strip()
        if token and chat_id:
            url = f"https://api.telegram.org/bot{token}/sendMessage"
            self._safe_send("Telegram", url, {"chat_id": chat_id, "text": self.build_telegram_text(event)})

    def _safe_send(self, channel: str, url: str, payload: dict[str, Any]) -> None:
        try:
            self._sender(url, payload)
        except urllib.error.HTTPError as e:
            log.error("%s alert rejected: HTTP %s", channel, e.code)  # never log the URL: it contains the secret
        except (urllib.error.URLError, OSError, ValueError) as e:
            log.error("%s alert failed: %s", channel, type(e).__name__)

    @staticmethod
    def _post_json(url: str, payload: dict[str, Any]) -> None:
        req = urllib.request.Request(
            url, method="POST", data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": "Monitro-SOC/2.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp.read(1024)
