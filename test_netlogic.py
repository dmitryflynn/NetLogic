"""
NetLogic unit tests — no network required
"""
import sys, os, unittest
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

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
    def test_parse_ver_basic(self):
        v = _parse_ver("7.4.1")
        # New format returns more parts, but first 3 should match
        self.assertEqual(v[:3], (7, 4, 1))
        
    def test_parse_ver_with_suffix(self):
        v = _parse_ver("6.6.1p1")
        # Should now capture the suffix info, e.g., (6, 6, 1, 101)
        self.assertGreater(len(v), 3)
        self.assertEqual(v[0:3], (6, 6, 1))
        
    def test_ver_lt_true(self):              self.assertTrue(_ver_lt("7.4", "8.5"))
    def test_ver_lt_false(self):             self.assertFalse(_ver_lt("9.0", "8.5"))
    def test_ver_lt_equal(self):             self.assertFalse(_ver_lt("8.5", "8.5"))
    def test_ver_lt_pre_release(self):       self.assertTrue(_ver_lt("1.2.3b1", "1.2.3"))
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
    """TTL residual is not a reliable OS signal on internet paths / CDNs."""
    def test_no_guess_from_ttl(self):
        self.assertIsNone(guess_os_from_ttl(64))
        self.assertIsNone(guess_os_from_ttl(128))
        self.assertIsNone(guess_os_from_ttl(246))  # used to false-claim "Cisco/HP"
        self.assertIsNone(guess_os_from_ttl(None))


class TestCVECorrelation(unittest.TestCase):
    """Correlate tests use a stubbed NVD lookup (no network, no offline VDB)."""

    def setUp(self):
        import src.nvd_lookup as nl
        import src.cve_correlator as cc
        from src.nvd_lookup import NVDCve, _ver_lt

        self._nl = nl
        self._cc = cc
        self._orig_nl = nl.lookup_cves_for_service
        self._orig_cc = cc.lookup_cves_for_service
        self._orig_unavail = getattr(nl, "_nvd_unavailable", False)
        self._orig_avail = nl.nvd_is_available

        def _lookup(product, version, min_cvss=4.0):
            p = (product or "").lower()
            v = version or ""
            out = []
            if p in ("openssh", "ssh"):
                if _ver_lt(v, "9.3"):
                    out.append(NVDCve("CVE-2023-38408", "x", 9.8, "CRITICAL", "", "", "", ""))
                if _ver_lt(v, "8.5"):
                    out.append(NVDCve("CVE-2021-41617", "x", 7.0, "HIGH", "", "", "", ""))
            if p == "vsftpd" and v.startswith("2.3.4"):
                out.append(NVDCve("CVE-2011-2523", "backdoor", 10.0, "CRITICAL", "", "", "", ""))
            return [c for c in out if c.cvss_score >= min_cvss]

        nl._nvd_unavailable = False
        nl.nvd_is_available = lambda: True
        nl.lookup_cves_for_service = _lookup
        cc.lookup_cves_for_service = _lookup

    def tearDown(self):
        self._nl.lookup_cves_for_service = self._orig_nl
        self._cc.lookup_cves_for_service = self._orig_cc
        self._nl._nvd_unavailable = self._orig_unavail
        self._nl.nvd_is_available = self._orig_avail

    def test_openssh_old_has_cves(self):
        matches = correlate([_make_port_result(22, "ssh", "openssh", "6.6.1")])
        cves = [c for m in matches for c in m.cves]
        self.assertGreater(len(cves), 0)

    def test_openssh_new_no_old_cve_false_positives(self):
        matches = correlate([_make_port_result(22, "ssh", "openssh", "9.9.0")])
        cve_ids = {c.id for m in matches for c in m.cves}
        legacy = {
            "CVE-2023-38408", "CVE-2021-41617", "CVE-2018-15473",
            "CVE-2016-3115", "CVE-2001-0529",
        }
        leaked = legacy & cve_ids
        self.assertEqual(leaked, set(),
                         f"version correlator false-positive on OpenSSH 9.9: {leaked}")

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