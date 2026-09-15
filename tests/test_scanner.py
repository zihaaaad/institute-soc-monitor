import socket
import struct
import threading
import unittest

from scanner import (
    ProbeResult, build_smbv1_negotiate_request, check_smbv1, on_link_networks, parse_arp_output,
    parse_smbv1_negotiate_response, probe_ports, sanitize_hostname,
)

WINDOWS_ARP_SAMPLE = """
Interface: 10.13.109.50 --- 0x7
  Internet Address      Physical Address      Type
  10.13.109.1           00-1b-d4-aa-bb-cc     dynamic
  10.13.109.23          E4-54-E8-11-22-33     dynamic
  10.13.109.255         ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
"""


def smb1_response(status=0, dialect_index=0):
    header = struct.pack("<4sBIBHH8sHHHHH", b"\xffSMB", 0x72, status, 0x98, 0xC853, 0, b"\0" * 8, 0, 0xFFFF, 0xFEFF, 0, 0)
    body = header + struct.pack("<BH", 1, dialect_index) + struct.pack("<H", 0)
    return b"\x00" + len(body).to_bytes(3, "big") + body


class FakeServer:
    """One-shot TCP server on 127.0.0.1 that replies with a fixed payload (or closes)."""

    def __init__(self, reply: bytes | None):
        self.reply = reply
        self.received = b""
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        conn, _ = self.sock.accept()
        with conn:
            conn.settimeout(2)
            try:
                self.received = conn.recv(4096)
            except OSError:
                pass
            if self.reply is not None:
                conn.sendall(self.reply)

    def close(self):
        self.thread.join(timeout=3)
        self.sock.close()


class SmbTests(unittest.TestCase):
    def test_request_lengths_are_consistent(self):
        pkt = build_smbv1_negotiate_request()
        self.assertEqual(int.from_bytes(pkt[1:4], "big"), len(pkt) - 4)
        self.assertEqual(pkt[4:8], b"\xffSMB")
        byte_count = struct.unpack("<H", pkt[37:39])[0]
        self.assertEqual(byte_count, len(pkt) - 39)
        self.assertNotIn(b"SMB 2", pkt)  # offering SMB2 would mask SMBv1 on dual-stack servers

    def test_response_parsing(self):
        self.assertTrue(parse_smbv1_negotiate_response(smb1_response()[4:]))
        self.assertFalse(parse_smbv1_negotiate_response(smb1_response(dialect_index=0xFFFF)[4:]))
        self.assertFalse(parse_smbv1_negotiate_response(smb1_response(status=0xC0000022)[4:]))
        self.assertFalse(parse_smbv1_negotiate_response(b"\xfeSMB" + b"\0" * 60))
        self.assertFalse(parse_smbv1_negotiate_response(b"\xffSMB"))

    def test_check_against_live_sockets(self):
        server = FakeServer(smb1_response())
        self.assertTrue(check_smbv1("127.0.0.1", timeout=2, port=server.port))
        server.close()
        self.assertEqual(server.received, build_smbv1_negotiate_request())

        server = FakeServer(None)  # SMBv1 disabled: server just closes
        self.assertFalse(check_smbv1("127.0.0.1", timeout=2, port=server.port))
        server.close()


class DiscoveryTests(unittest.TestCase):
    def test_arp_parsing_drops_broadcast_and_multicast(self):
        self.assertEqual(parse_arp_output(WINDOWS_ARP_SAMPLE),
                         {"10.13.109.1": "00:1b:d4:aa:bb:cc", "10.13.109.23": "e4:54:e8:11:22:33"})

    def test_hostname_sanitization(self):
        self.assertEqual(sanitize_hostname("LAB-PC-07.campus.local."), "LAB-PC-07.campus.local")
        self.assertEqual(sanitize_hostname("<img src=x onerror=alert(1)>"), "imgsrcxonerroralert1")
        self.assertEqual(sanitize_hostname(None), "")

    def test_probe_open_port_and_rtt(self):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(5)
        port = listener.getsockname()[1]
        try:
            result = probe_ports("127.0.0.1", [port], timeout=1.0)
        finally:
            listener.close()
        self.assertIsInstance(result, ProbeResult)
        self.assertTrue(result.responded)
        self.assertEqual(result.open_ports, [port])
        self.assertIsNotNone(result.rtt_ms)

    def test_on_link_networks(self):
        nets = on_link_networks("10.13.109.50", ["10.13.109.0/24", "10.13.110.0/24"])
        self.assertEqual([str(n) for n in nets], ["10.13.109.0/24"])


if __name__ == "__main__":
    unittest.main()
