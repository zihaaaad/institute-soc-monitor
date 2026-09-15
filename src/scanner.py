"""Agentless network discovery primitives: TCP probes, ARP, NetBIOS/DNS names, SMBv1.

Everything here is read-only and defensive: TCP connects that are closed
immediately, one SMB negotiate request, one NetBIOS node-status query.
No exploitation, no authentication.
"""
from __future__ import annotations

import ctypes
import errno
import ipaddress
import logging
import random
import re
import socket
import struct
import subprocess
import threading
import time
from dataclasses import dataclass, field

from config_loader import normalize_mac

log = logging.getLogger("monitro.scanner")

# TCP services fingerprinted on live hosts. UDP services (SNMP 161, SIP 5060/udp)
# cannot be detected with a TCP connect and are deliberately not listed.
PORT_SERVICE_MAP: dict[int, str] = {
    # Windows & Active Directory
    135: "RPC/WMI",
    139: "NetBIOS",
    445: "SMB/Shares",
    3389: "RDP/Remote",
    5985: "WinRM",
    # Web & management interfaces
    80: "HTTP",
    443: "HTTPS",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Admin",
    8000: "Web-App",
    8888: "Web-Admin",
    # Remote management & shells
    22: "SSH",
    23: "Telnet",
    21: "FTP",
    5900: "VNC",
    # Network infrastructure
    53: "DNS",
    # Surveillance
    554: "RTSP-Camera",
    8899: "ONVIF-Camera",
    # Printers
    9100: "JetDirect-Printer",
    631: "IPP-Printer",
    # Telephony & databases
    5060: "SIP-VoIP",
    1433: "MSSQL",
    3306: "MySQL",
    5432: "PostgreSQL",
}

# Small set probed on every IP each cycle to decide liveness. One port per common
# device class keeps a 31 x /24 sweep to tens of seconds instead of minutes.
DISCOVERY_PORTS: tuple[int, ...] = (80, 443, 445, 135, 22, 3389, 554, 9100, 23)

_REFUSED = {errno.ECONNREFUSED, 10061}
_HOSTNAME_INVALID = re.compile(r"[^A-Za-z0-9._-]")


@dataclass
class ProbeResult:
    ip: str
    responded: bool = False
    open_ports: list[int] = field(default_factory=list)
    rtt_ms: float | None = None


def probe_ports(ip: str, ports: list[int] | tuple[int, ...], timeout: float, stop_on_first: bool = False) -> ProbeResult:
    """TCP connect probe. An open port or an explicit RST both prove the host is up.

    rtt_ms is the fastest handshake/RST observed, i.e. real network latency,
    not the time spent waiting on filtered ports.
    """
    result = ProbeResult(ip=ip)
    for port in ports:
        start = time.perf_counter()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                code = s.connect_ex((ip, port))
        except OSError:
            continue
        elapsed_ms = (time.perf_counter() - start) * 1000
        if code == 0 or code in _REFUSED:
            result.responded = True
            if result.rtt_ms is None or elapsed_ms < result.rtt_ms:
                result.rtt_ms = round(elapsed_ms, 2)
            if code == 0:
                result.open_ports.append(port)
                if stop_on_first:
                    break
    return result


# ---------------------------------------------------------------------------
# ARP
# ---------------------------------------------------------------------------
_ARP_LINE = re.compile(r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})\s", re.M)


def parse_arp_output(text: str) -> dict[str, str]:
    """Parse `arp -a` output into {ip: mac}, dropping broadcast/multicast entries."""
    entries: dict[str, str] = {}
    for ip, raw_mac in _ARP_LINE.findall(text + "\n"):
        mac = normalize_mac(raw_mac)
        if mac is None or int(mac[:2], 16) & 0x01 or mac == "00:00:00:00:00:00":
            continue
        entries[ip] = mac
    return entries


def read_arp_cache() -> dict[str, str]:
    try:
        proc = subprocess.run(["arp", "-a"], capture_output=True, timeout=15, check=False)
    except (OSError, subprocess.TimeoutExpired) as e:
        log.warning("Could not read ARP cache: %s", e)
        return {}
    return parse_arp_output(proc.stdout.decode("utf-8", errors="ignore"))


def sendarp_mac(ip: str) -> str | None:
    """Resolve a MAC with Win32 SendARP. Only meaningful for on-link addresses."""
    try:
        send_arp = ctypes.windll.iphlpapi.SendARP  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        return None
    try:
        dest = ctypes.c_ulong(struct.unpack("<I", socket.inet_aton(ip))[0])
        buf = (ctypes.c_ubyte * 6)()
        length = ctypes.c_ulong(6)
        if send_arp(dest, 0, ctypes.byref(buf), ctypes.byref(length)) != 0 or length.value != 6:
            return None
    except (OSError, ValueError, struct.error):
        return None
    mac = ":".join(f"{b:02x}" for b in bytes(buf))
    return None if mac == "00:00:00:00:00:00" else mac


def on_link_networks(local_ip: str, subnets: list[str]) -> list[ipaddress.IPv4Network]:
    """Configured subnets that contain this host, i.e. where ARP is authoritative."""
    try:
        addr = ipaddress.IPv4Address(local_ip)
    except ValueError:
        return []
    return [net for net in (ipaddress.IPv4Network(s) for s in subnets) if addr in net]


# ---------------------------------------------------------------------------
# Names
# ---------------------------------------------------------------------------
def sanitize_hostname(name: str | None) -> str:
    """Keep only RFC 1123 characters. Hostnames are attacker-controlled input
    (reverse DNS, NetBIOS, LLMNR) and end up in dashboards, reports and alerts."""
    if not name:
        return ""
    cleaned = _HOSTNAME_INVALID.sub("", name.strip().rstrip("."))
    return cleaned[:253]


def netbios_name(ip: str, timeout: float = 0.5) -> str:
    """NetBIOS node status (NBSTAT) query; returns the workstation name if any."""
    txid = random.randint(0, 0xFFFF)
    query = struct.pack(">HHHHHH", txid, 0x0000, 1, 0, 0, 0) + b"\x20" + b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" + b"\x00" + struct.pack(">HH", 0x0021, 0x0001)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(query, (ip, 137))
            data, addr = s.recvfrom(2048)
    except OSError:
        return ""
    if addr[0] != ip or len(data) < 57 or struct.unpack(">H", data[:2])[0] != txid:
        return ""
    count = data[56]
    offset = 57
    for _ in range(count):
        if offset + 18 > len(data):
            break
        raw = data[offset:offset + 15]
        suffix = data[offset + 15]
        flags = struct.unpack(">H", data[offset + 16:offset + 18])[0]
        offset += 18
        is_group = bool(flags & 0x8000)
        if suffix == 0x00 and not is_group:
            return sanitize_hostname(raw.decode("ascii", errors="ignore"))
    return ""


class HostnameResolver:
    """NetBIOS then reverse DNS, cached with a TTL so DHCP re-assignments age out."""

    def __init__(self, ttl_seconds: float = 3600, negative_ttl_seconds: float = 600, netbios_timeout: float = 0.5):
        self._cache: dict[str, tuple[str, str, float]] = {}
        self._lock = threading.Lock()
        self.ttl = ttl_seconds
        self.negative_ttl = negative_ttl_seconds
        self.netbios_timeout = netbios_timeout

    def resolve(self, ip: str) -> tuple[str, str]:
        now = time.monotonic()
        with self._lock:
            cached = self._cache.get(ip)
            if cached and cached[2] > now:
                return cached[0], cached[1]

        name, source = netbios_name(ip, self.netbios_timeout), "netbios"
        if not name:
            try:
                name, source = sanitize_hostname(socket.gethostbyaddr(ip)[0]), "dns"
            except OSError:
                name, source = "", "none"

        with self._lock:
            self._cache[ip] = (name, source, now + (self.ttl if name else self.negative_ttl))
        return name, source


# ---------------------------------------------------------------------------
# SMBv1
# ---------------------------------------------------------------------------
def build_smbv1_negotiate_request() -> bytes:
    """SMB_COM_NEGOTIATE offering only the NT LM 0.12 (SMBv1) dialect.

    Offering an SMB2 dialect as well would let dual-stack servers answer with
    SMB2 and hide the fact that SMBv1 is still enabled.
    """
    header = struct.pack(
        "<4sBIBHH8sHHHHH",
        b"\xffSMB",   # Protocol
        0x72,         # SMB_COM_NEGOTIATE
        0,            # NT status
        0x18,         # Flags: canonicalized paths, case-insensitive
        0xC801,       # Flags2: unicode, NT status, extended security, long names
        0,            # PID high
        b"\x00" * 8,  # Security features
        0,            # Reserved
        0xFFFF,       # TID
        0xFEFF,       # PID low
        0,            # UID
        0,            # MID
    )
    dialects = b"\x02NT LM 0.12\x00"
    body = header + struct.pack("<BH", 0, len(dialects)) + dialects
    return b"\x00" + len(body).to_bytes(3, "big") + body


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = sock.recv(size - len(chunks))
        if not chunk:
            break
        chunks.extend(chunk)
    return bytes(chunks)


def parse_smbv1_negotiate_response(body: bytes) -> bool:
    """True only for a successful SMBv1 negotiate that selected a dialect."""
    if len(body) < 35 or body[:4] != b"\xffSMB" or body[4] != 0x72:
        return False
    status = struct.unpack("<I", body[5:9])[0]
    word_count = body[32]
    if status != 0 or word_count < 1:
        return False
    dialect_index = struct.unpack("<H", body[33:35])[0]
    return dialect_index != 0xFFFF


def check_smbv1(ip: str, timeout: float = 1.5, port: int = 445) -> bool | None:
    """True = SMBv1 accepted, False = rejected, None = inconclusive (no connection)."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(build_smbv1_negotiate_request())
            nb_header = _recv_exact(s, 4)
            if len(nb_header) < 4:
                return False  # connection closed: SMBv1 refused
            length = int.from_bytes(nb_header[1:4], "big")
            body = _recv_exact(s, min(length, 4096))
    except ConnectionResetError:
        return False
    except OSError:
        return None
    return parse_smbv1_negotiate_response(body)
