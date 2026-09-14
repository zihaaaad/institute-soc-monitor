"""Configuration loading shared by every Monitro entry point.

Precedence, lowest to highest:
  1. DEFAULT_CONFIG below
  2. config.json        - tracked in git, must never contain secrets
  3. config.local.json  - git-ignored, site overrides and secrets
  4. MONITRO_* environment variables (see ENV_OVERRIDES)

Invalid configuration fails loudly. A security monitor that silently falls
back to scanning a different network is worse than one that refuses to start.
"""
from __future__ import annotations

import copy
import ipaddress
import json
import logging
import os
import re
import socket
from typing import Any, Mapping

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
LOCAL_CONFIG_PATH = os.path.join(BASE_DIR, "config.local.json")
LOG_DIR = os.path.join(BASE_DIR, "logs")

log = logging.getLogger("monitro.config")

# Larger ranges make a single sweep take minutes and look like a scan storm to IDS.
MAX_HOSTS_PER_SUBNET = 4094  # /20

MAC_RE = re.compile(r"^([0-9a-f]{2})([:-]?)([0-9a-f]{2})\2([0-9a-f]{2})\2([0-9a-f]{2})\2([0-9a-f]{2})\2([0-9a-f]{2})$", re.I)

DEFAULT_CONFIG: dict[str, Any] = {
    "subnets": {},
    "allow_public_ranges": False,
    "credentials": {
        "windows_user": "",
        "windows_password": "",
        "windows_authority": "",
    },
    "settings": {
        "scan_interval_seconds": 60,
        "metrics_port": 8000,
        "metrics_bind_address": "127.0.0.1",
        "prometheus_url": "http://127.0.0.1:9090",
        "grafana_url": "http://127.0.0.1:3000",
        "probe_timeout_seconds": 0.25,
        "probe_workers": 128,
        "dns_timeout_seconds": 2.0,
    },
    "asset_whitelist": [],
    "alerts": {
        "enabled": False,
        "discord_webhook_url": "",
        "telegram_bot_token": "",
        "telegram_chat_id": "",
        "alert_cooldown_seconds": 900,
    },
    "vulnerability_audit": {
        "enabled": True,
        "check_smbv1": True,
        "check_rdp_exposure": True,
        "check_cleartext_protocols": True,
        "check_rpc_mapper": True,
    },
    "wmi_audit": {
        "enabled": True,
        "audit_unverified_hosts": False,
        "max_concurrent_audits": 16,
        "event_lookback_minutes": 15,
        "brute_force_threshold": 10,
        "password_spray_account_threshold": 5,
    },
    "suspicious_processes": [
        "mimikatz.exe", "psexec.exe", "psexesvc.exe", "netcat.exe", "nc.exe", "ncat.exe",
        "nmap.exe", "wireshark.exe", "tor.exe", "anydesk.exe", "teamviewer.exe",
        "procdump.exe", "rubeus.exe", "sharphound.exe", "lazagne.exe",
    ],
    # Built-in command-line rules live in threat_intel.COMMANDLINE_RULES; add site-specific regexes here.
    "extra_commandline_patterns": [],
    "dashboard": {
        "bind_address": "127.0.0.1",
        "port": 5000,
        "username": "",
        "password": "",
    },
}

# (environment variable, config path)
ENV_OVERRIDES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("MONITRO_WINDOWS_USER", ("credentials", "windows_user")),
    ("MONITRO_WINDOWS_PASSWORD", ("credentials", "windows_password")),
    ("MONITRO_WINDOWS_AUTHORITY", ("credentials", "windows_authority")),
    ("MONITRO_DISCORD_WEBHOOK_URL", ("alerts", "discord_webhook_url")),
    ("MONITRO_TELEGRAM_BOT_TOKEN", ("alerts", "telegram_bot_token")),
    ("MONITRO_TELEGRAM_CHAT_ID", ("alerts", "telegram_chat_id")),
    ("MONITRO_DASHBOARD_USER", ("dashboard", "username")),
    ("MONITRO_DASHBOARD_PASSWORD", ("dashboard", "password")),
)

# Values that must never live in the git-tracked config.json
SECRET_PATHS: tuple[tuple[str, ...], ...] = (
    ("credentials", "windows_password"),
    ("alerts", "discord_webhook_url"),
    ("alerts", "telegram_bot_token"),
    ("dashboard", "password"),
)


class ConfigError(Exception):
    """Raised when configuration is unreadable or unsafe to run with."""


def deep_merge(base: dict[str, Any], override: Mapping[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, Mapping) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def get_local_ip() -> str:
    """Primary IPv4 of this host. The UDP connect sends no packets."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 9))  # TEST-NET-1, never routed
            return s.getsockname()[0]
    except OSError:
        try:
            return socket.gethostbyname(socket.gethostname())
        except OSError:
            return "127.0.0.1"


def normalize_mac(value: str) -> str | None:
    """Return a MAC as lowercase colon-separated form, or None if invalid."""
    if not isinstance(value, str):
        return None
    m = MAC_RE.match(value.strip())
    if not m:
        return None
    return ":".join(m.group(i).lower() for i in (1, 3, 4, 5, 6, 7))


def _read_json(path: str) -> dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        raise ConfigError(f"{os.path.basename(path)} is not valid JSON: {e}") from e
    except OSError as e:
        raise ConfigError(f"Cannot read {path}: {e}") from e
    if not isinstance(data, dict):
        raise ConfigError(f"{os.path.basename(path)} must contain a JSON object")
    return data


def _get_path(cfg: Mapping[str, Any], path: tuple[str, ...]) -> Any:
    node: Any = cfg
    for part in path:
        if not isinstance(node, Mapping):
            return None
        node = node.get(part)
    return node


def _set_path(cfg: dict[str, Any], path: tuple[str, ...], value: Any) -> None:
    node = cfg
    for part in path[:-1]:
        node = node.setdefault(part, {})
    node[path[-1]] = value


def validate_subnets(subnets: Mapping[str, str], allow_public: bool) -> dict[str, str]:
    valid: dict[str, str] = {}
    for raw, lab_name in subnets.items():
        try:
            net = ipaddress.IPv4Network(raw, strict=False)
        except ValueError as e:
            log.error("Ignoring invalid subnet %r: %s", raw, e)
            continue
        if net.num_addresses - 2 > MAX_HOSTS_PER_SUBNET:
            log.error("Ignoring subnet %s: larger than /20 (%d hosts). Split it into smaller ranges.", net, net.num_addresses)
            continue
        if not net.is_private and not allow_public:
            log.error("Ignoring non-private subnet %s. Only scan networks you are authorised to test "
                      "(set allow_public_ranges=true to override).", net)
            continue
        valid[str(net)] = str(lab_name) if lab_name else str(net)
    return valid


def load_config(
    config_path: str = CONFIG_PATH,
    local_path: str = LOCAL_CONFIG_PATH,
    environ: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    environ = os.environ if environ is None else environ
    cfg = copy.deepcopy(DEFAULT_CONFIG)

    if os.path.exists(config_path):
        tracked = _read_json(config_path)
        for path in SECRET_PATHS:
            if _get_path(tracked, path):
                log.warning("SECURITY: %s is set in %s, which is tracked by git. Move it to "
                            "config.local.json or an environment variable.", ".".join(path), os.path.basename(config_path))
        cfg = deep_merge(cfg, tracked)

    if os.path.exists(local_path):
        cfg = deep_merge(cfg, _read_json(local_path))

    for env_name, path in ENV_OVERRIDES:
        if environ.get(env_name):
            _set_path(cfg, path, environ[env_name])

    # Backwards compatibility with the previous key name
    vuln = cfg["vulnerability_audit"]
    if "check_cleartext_http" in vuln:
        vuln["check_cleartext_protocols"] = vuln.pop("check_cleartext_http")

    local_ip = get_local_ip()
    cfg["local_ip"] = local_ip

    subnets = validate_subnets(cfg.get("subnets") or {}, bool(cfg.get("allow_public_ranges")))
    if not subnets:
        if cfg.get("subnets"):
            raise ConfigError("No valid subnets left after validation; fix the 'subnets' section.")
        auto = str(ipaddress.IPv4Network(f"{local_ip}/24", strict=False))
        log.warning("No subnets configured; auto-detected local network %s", auto)
        subnets = {auto: "Local Network"}
    cfg["subnets"] = subnets

    whitelist: set[str] = set()
    for entry in cfg.get("asset_whitelist") or []:
        mac = normalize_mac(entry)
        if mac:
            whitelist.add(mac)
        else:
            log.error("Ignoring invalid asset_whitelist entry %r (expected a MAC address)", entry)
    cfg["asset_whitelist"] = sorted(whitelist)
    if not whitelist:
        log.warning("asset_whitelist is empty: rogue-device detection is disabled. "
                    "Run 'python src\\agentless_monitor_win.py --export-baseline' to build one.")

    cfg["suspicious_processes"] = sorted({str(p).lower() for p in cfg.get("suspicious_processes") or []})
    patterns = []
    for pattern in cfg.get("extra_commandline_patterns") or []:
        try:
            patterns.append(re.compile(pattern))
        except (re.error, TypeError) as e:
            log.error("Ignoring invalid extra_commandline_patterns entry %r: %s", pattern, e)
    cfg["compiled_commandline_patterns"] = patterns

    settings = cfg["settings"]
    try:
        settings["scan_interval_seconds"] = max(15, int(settings["scan_interval_seconds"]))
        settings["metrics_port"] = int(settings["metrics_port"])
        settings["probe_timeout_seconds"] = min(max(float(settings["probe_timeout_seconds"]), 0.05), 5.0)
        settings["probe_workers"] = min(max(int(settings["probe_workers"]), 1), 512)
        settings["dns_timeout_seconds"] = min(max(float(settings["dns_timeout_seconds"]), 0.1), 10.0)
    except (TypeError, ValueError) as e:
        raise ConfigError(f"Invalid value in 'settings': {e}") from e

    return cfg
