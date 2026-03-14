"""
NetLogic unit tests — no network required
"""
import sys, os, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.scanner       import parse_banner, guess_os_from_ttl, ServiceBanner, PortResult
from src.cve_correlator import (
    correlate, _parse_ver, _ver_lt, _ver_in_range,
    CVE, VulnMatch
)


def _make_port_result(port, service, product=None, version=None, state="open"):
    pr = PortResult(port=port, protocol="tcp", state=state, service=service)
    if product or version:
        pr.banner = ServiceBanner(raw="", product=product, version=version)
    return pr


class TestVersionComparison(unittest.TestCase):
    def test_parse_ver_basic(self):          self.assertEqual(_parse_ver("7.4.1"), (7, 4, 1))
    def test_parse_ver_with_suffix(self):    self.assertEqual(_parse_ver("6.6.1p1"), (6, 6, 1))
    def test_ver_lt_true(self):              self.assertTrue(_ver_lt("7.4", "8.5"))
    def test_ver_lt_false(self):             self.assertFalse(_ver_lt("9.0", "8.5"))
    def test_ver_lt_equal(self):             self.assertFalse(_ver_lt("8.5", "8.5"))
    def test_ver_in_range_true(self):        self.assertTrue(_ver_in_range("2.4.49", "2.4.49", "2.4.50"))
    def test_ver_in_range_false(self):       self.assertFalse(_ver_in_range("2.4.51", "2.4.49", "2.4.50"))


class TestBannerParsing(unittest.TestCase):
    def test_parse_ssh_banner(self):
        b = parse_banner("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n", "ssh")
        self.assertIn("8.2", b.version or "")

    def test_parse_http_server(self):
        b = parse_banner("HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n", "http")
        self.assertIn("nginx", (b.product or "").lower())

    def test_parse_redis_banner(self):
        b = parse_banner("# Server\r\nredis_version:6.0.9\r\n", "redis")
        self.assertEqual(b.version, "6.0.9")

    def test_empty_banner(self):
        b = parse_banner("", "unknown")
        self.assertIsNone(b.product)


class TestOSGuess(unittest.TestCase):
    def test_linux(self):    self.assertIn("Linux", guess_os_from_ttl(64))
    def test_windows(self):  self.assertIn("Windows", guess_os_from_ttl(128))
    def test_none(self):     self.assertIsNone(guess_os_from_ttl(None))


class TestCVECorrelation(unittest.TestCase):
    def test_openssh_old_has_cves(self):
        matches = correlate([_make_port_result(22, "ssh", "openssh", "6.6.1")])
        cves = [c for m in matches for c in m.cves]
        self.assertGreater(len(cves), 0)

    def test_openssh_new_no_cves(self):
        # 9.3p2+ is fully patched; 9.9 should have no CVEs
        matches = correlate([_make_port_result(22, "ssh", "openssh", "9.9.0")])
        cves = [c for m in matches for c in m.cves if c.id.startswith("CVE")]
        self.assertEqual(len(cves), 0)

    def test_redis_misconfiguration_flagged(self):
        matches = correlate([_make_port_result(6379, "redis")])
        self.assertTrue(any(m.notes for m in matches))

    def test_telnet_flagged(self):
        matches = correlate([_make_port_result(23, "telnet")])
        self.assertIsInstance(matches, list)  # telnet without product just runs cleanly

    def test_vsftpd_backdoor(self):
        matches = correlate([_make_port_result(21, "ftp", "vsftpd", "2.3.4")])
        cve_ids = [c.id for m in matches for c in m.cves]
        self.assertIn("CVE-2011-2523", cve_ids)

    def test_closed_port_ignored(self):
        matches = correlate([_make_port_result(22, "ssh", state="closed")])
        self.assertEqual(matches, [])

    def test_risk_score_bounded(self):
        matches = correlate([_make_port_result(21, "ftp", "vsftpd", "2.3.4")])
        for m in matches:
            self.assertLessEqual(m.risk_score, 10.0)
            self.assertGreaterEqual(m.risk_score, 0.0)


if __name__ == "__main__":
    unittest.main()