import base64
import collections
import unittest

try:
    from fastapi.testclient import TestClient
except ImportError:  # httpx missing: pip install -r requirements-dev.txt
    TestClient = None

from soc_dashboard import create_app, is_loopback


class FakeEngine:
    subnets = {"10.0.0.0/24": "Lab"}
    is_scanning = False
    config = {"settings": {"scan_interval_seconds": 60}}

    def __init__(self):
        self.runs = 0

    def latest(self):
        return None

    def try_run_cycle(self):
        self.runs += 1


class FakeAuditor:
    def results(self):
        return {}


class FakeDispatcher:
    recent = collections.deque([{"timestamp": "t", "severity": "HIGH", "title": "<b>x</b>", "target_ip": "10.0.0.1",
                                 "message": "m", "evidence": "secret", "type": "rogue"}])


@unittest.skipIf(TestClient is None, "httpx not installed")
class DashboardTests(unittest.TestCase):
    def client(self, username="", password=""):
        config = {"settings": {"scan_interval_seconds": 60}, "dashboard": {"username": username, "password": password}}
        self.engine = FakeEngine()
        app = create_app(config, self.engine, FakeAuditor(), FakeDispatcher(), run_background=False)
        return TestClient(app)

    def test_security_headers_and_no_cdn(self):
        response = self.client().get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("script-src 'self'", response.headers["content-security-policy"])
        self.assertEqual(response.headers["x-frame-options"], "DENY")
        self.assertNotIn("cdn", response.text.lower())

    def test_auth_required_when_configured(self):
        client = self.client("soc", "correct horse battery")
        self.assertEqual(client.get("/api/summary").status_code, 401)
        bad = base64.b64encode(b"soc:wrong").decode()
        self.assertEqual(client.get("/api/summary", headers={"Authorization": f"Basic {bad}"}).status_code, 401)
        good = base64.b64encode(b"soc:correct horse battery").decode()
        response = client.get("/api/summary", headers={"Authorization": f"Basic {good}"})
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(response.json()["compliance_percent"])

    def test_scan_now_requires_csrf_header(self):
        client = self.client()
        self.assertEqual(client.post("/api/scan-now").status_code, 403)
        self.assertEqual(client.post("/api/scan-now", headers={"X-Monitro-Request": "1"}).status_code, 202)

    def test_alert_api_does_not_leak_evidence(self):
        alerts = self.client().get("/api/alerts").json()
        self.assertEqual(alerts[0]["title"], "<b>x</b>")  # raw JSON; the UI renders with textContent
        self.assertNotIn("evidence", alerts[0])

    def test_docs_disabled(self):
        self.assertEqual(self.client().get("/docs").status_code, 404)

    def test_is_loopback(self):
        self.assertTrue(is_loopback("127.0.0.1"))
        self.assertTrue(is_loopback("::1"))
        self.assertFalse(is_loopback("0.0.0.0"))


if __name__ == "__main__":
    unittest.main()
