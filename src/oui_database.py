"""MAC address -> hardware vendor resolution.

Lookup order:
  1. The official IEEE MA-L registry at data/oui.csv (setup.bat downloads it from
     https://standards-oui.ieee.org/oui/oui.csv). This is authoritative.
  2. BUILTIN_OUI_FALLBACK, a small offline table. Every entry was cross-checked
     against the IEEE registry (2026-09); virtualisation prefixes that are
     locally administered and therefore absent from the registry are marked.
  3. Address-bit classification (randomised / locally administered MACs).

A MAC vendor only identifies the NIC manufacturer. It is trivially spoofable
and must not be treated as proof of device identity.
"""
from __future__ import annotations

import csv
import logging
import os
import threading

from config_loader import BASE_DIR, normalize_mac

OUI_CSV_PATH = os.path.join(BASE_DIR, "data", "oui.csv")
UNKNOWN_MAC_VENDOR = "Unknown (MAC not visible)"

log = logging.getLogger("monitro.oui")

BUILTIN_OUI_FALLBACK: dict[str, str] = {
    # Virtualisation
    "00:50:56": "VMware, Inc.",
    "00:0c:29": "VMware, Inc.",
    "00:05:69": "VMware, Inc.",
    "00:15:5d": "Microsoft Corporation (Hyper-V)",
    "08:00:27": "PCS Systemtechnik GmbH (VirtualBox)",
    "00:16:3e": "Xensource, Inc.",
    "52:54:00": "QEMU/KVM virtual NIC (locally administered)",
    "02:42:ac": "Docker bridge (locally administered)",
    # PC, NIC and motherboard vendors
    "00:1b:21": "Intel Corporate",
    "00:1e:67": "Intel Corporate",
    "28:d0:ea": "Intel Corporate",
    "00:16:76": "Intel Corporate",
    "00:e0:4c": "REALTEK SEMICONDUCTOR CORP.",
    "e4:54:e8": "Dell Inc.",
    "00:14:22": "Dell Inc.",
    "18:03:73": "Dell Inc.",
    "b8:ac:6f": "Dell Inc.",
    "00:1e:0b": "Hewlett Packard",
    "3c:52:82": "Hewlett Packard",
    "70:85:c2": "ASRock Incorporation",
    "10:7c:61": "ASUSTek COMPUTER INC.",
    "4c:ed:fb": "ASUSTek COMPUTER INC.",
    "08:bf:b8": "ASUSTek COMPUTER INC.",
    "70:4d:7b": "ASUSTek COMPUTER INC.",
    "04:d9:f5": "ASUSTek COMPUTER INC.",
    "54:04:a6": "ASUSTek COMPUTER INC.",
    "50:eb:f6": "ASUSTek COMPUTER INC.",
    "34:5a:60": "Micro-Star INTL CO., LTD.",
    "d8:5e:d3": "GIGA-BYTE TECHNOLOGY CO.,LTD.",
    "e0:d5:5e": "GIGA-BYTE TECHNOLOGY CO.,LTD.",
    "1c:1b:0d": "GIGA-BYTE TECHNOLOGY CO.,LTD.",
    "ac:e0:10": "Liteon Technology Corporation",
    "54:ee:75": "Wistron InfoComm(Kunshan)Co.,Ltd.",
    # Network infrastructure
    "00:00:0c": "Cisco Systems, Inc",
    "00:1b:d4": "Cisco Systems, Inc",
    "64:d8:14": "Cisco Systems, Inc",
    "70:70:8b": "Cisco Systems, Inc",
    "14:d6:4d": "D-Link International",
    "50:c7:bf": "TP-LINK TECHNOLOGIES CO.,LTD.",
    "ec:08:6b": "TP-LINK TECHNOLOGIES CO.,LTD.",
    "30:b5:c2": "TP-LINK TECHNOLOGIES CO.,LTD.",
    "b0:19:21": "TP-Link Systems Inc",
    "48:8f:5a": "Routerboard.com (MikroTik)",
    "cc:2d:e0": "Routerboard.com (MikroTik)",
    "d4:01:c3": "Routerboard.com (MikroTik)",
    "74:4d:28": "Routerboard.com (MikroTik)",
    "fc:ec:da": "Ubiquiti Inc",
    "00:24:b2": "NETGEAR",
    "a0:04:60": "NETGEAR",
    "00:04:96": "Extreme Networks, Inc.",
    "00:0b:86": "Hewlett Packard Enterprise (Aruba)",
    "00:17:88": "Philips Lighting BV",
    # Mobile, IoT and single-board computers (common rogue devices)
    "a4:83:e7": "Apple, Inc.",
    "f0:18:98": "Apple, Inc.",
    "3c:06:30": "Apple, Inc.",
    "ac:bc:32": "Apple, Inc.",
    "00:26:08": "Apple, Inc.",
    "78:02:f8": "Xiaomi Communications Co Ltd",
    "60:ab:67": "Xiaomi Communications Co Ltd",
    "28:6c:07": "XIAOMI Electronics,CO.,LTD",
    "50:01:d9": "HUAWEI TECHNOLOGIES CO.,LTD",
    "88:36:5f": "LG Electronics (Mobile Communications)",
    "28:ff:3e": "zte corporation",
    "00:1a:11": "Google, Inc.",
    "b8:27:eb": "Raspberry Pi Foundation",
    "dc:a6:32": "Raspberry Pi Trading Ltd",
    "e4:5f:01": "Raspberry Pi Trading Ltd",
    "24:0a:c4": "Espressif Inc. (ESP32/ESP8266 IoT)",
}

_registry: dict[str, str] | None = None
_registry_lock = threading.Lock()


def load_ieee_registry(path: str = OUI_CSV_PATH) -> dict[str, str]:
    """Parse the IEEE MA-L CSV (Registry,Assignment,Organization Name,...)."""
    registry: dict[str, str] = {}
    if not os.path.exists(path):
        return registry
    try:
        with open(path, "r", encoding="utf-8", errors="replace", newline="") as f:
            for row in csv.DictReader(f):
                assignment = (row.get("Assignment") or "").strip().lower()
                org = (row.get("Organization Name") or "").strip()
                if len(assignment) == 6 and org:
                    registry[f"{assignment[0:2]}:{assignment[2:4]}:{assignment[4:6]}"] = org
    except (OSError, csv.Error) as e:
        log.warning("Could not parse IEEE OUI registry %s: %s", path, e)
        return {}
    return registry


def _get_registry() -> dict[str, str]:
    global _registry
    if _registry is None:
        with _registry_lock:
            if _registry is None:
                _registry = load_ieee_registry()
                if _registry:
                    log.info("Loaded %d vendor prefixes from IEEE registry", len(_registry))
                else:
                    log.info("IEEE registry not found at %s; using built-in fallback table", OUI_CSV_PATH)
    return _registry


def lookup_mac_vendor(mac_address: str | None, registry: dict[str, str] | None = None) -> str:
    mac = normalize_mac(mac_address) if mac_address else None
    if mac is None:
        return UNKNOWN_MAC_VENDOR

    prefix = mac[:8]
    registry = _get_registry() if registry is None else registry
    if prefix in registry:
        return registry[prefix]
    if prefix in BUILTIN_OUI_FALLBACK:
        return BUILTIN_OUI_FALLBACK[prefix]

    first_octet = int(mac[:2], 16)
    if first_octet & 0x01:
        return "Multicast / Broadcast address"
    if first_octet & 0x02:
        return "Randomized / Locally Administered MAC"
    return "Unregistered Vendor"
