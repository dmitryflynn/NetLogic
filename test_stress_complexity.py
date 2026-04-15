import sys, os, unittest, json, time, random
from dataclasses import asdict

# Path bootstrap
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

from src.scanner import parse_banner, ServiceBanner, resolve_target
from src.json_bridge import emit, _vuln_to_dict
from src.cve_correlator import VulnMatch, CVE
from api.jobs.manager import job_manager, ScanJob
from api.models.scan_request import ScanRequest

class TestStressAndComplexity(unittest.TestCase):

    def test_cidr_resolution_edge_cases(self):
        print("  - Testing CIDR and Resolution edge cases...")
        # Test basic resolution
        ip, host = resolve_target("127.0.0.1")
        self.assertEqual(ip, "127.0.0.1")
        
        # Test invalid target (should not crash)
        ip, host = resolve_target("this.is.not.a.valid.host.12345")
        self.assertIsNotNone(ip) # Should return the original string as fallback
        
    def test_banner_parser_robustness(self):
        print("  - Testing Banner Parser with malicious/extreme inputs...")
        
        # 1. Extremely large banner (100KB) to test memory/regex performance
        large_banner = "Server: " + ("A" * 100000)
        result = parse_banner(large_banner, "http")
        self.assertEqual(result.product, "A" * 100000)
        
        # 2. Binary data in banner (OpenSSH case)
        binary_banner = "SSH-2.0-OpenSSH_8.9\x00\xff\xfe\x01\x02"
        result = parse_banner(binary_banner, "ssh")
        self.assertEqual(result.version, "8.9")
        
        # 3. ReDoS attempt
        evil_banner = "Server: " + ("/" * 5000) + "1.2.3"
        result = parse_banner(evil_banner, "http")
        self.assertIn("1.2.3", result.version or "")

    def test_json_bridge_serialization_safety(self):
        print("  - Testing JSON Bridge serialization with complex/broken data...")
        
        # Mock a complex VulnMatch with all required fields
        vm = VulnMatch(
            port=80, service="http", product="Apache", version="2.4.49",
            risk_score=9.8, notes=["Note 1", "Note 2"],
            cves=[
                CVE(id="CVE-2021-41773", description="Path Traversal", 
                    cvss_score=9.8, severity="CRITICAL", exploit_available=True,
                    vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", published="2021-10-05")
            ]
        )
        
        # Ensure conversion to dict works and handles missing attributes safely
        d = _vuln_to_dict(vm)
        self.assertEqual(d["port"], 80)
        self.assertEqual(len(d["cves"]), 1)
        self.assertEqual(d["cves"][0]["vector"], "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        
        # Test with extremely nested/weird data
        complex_data = {"key": {"nested": [1, 2, {"more": "data"}]}, "unicode": "🛡️🔒🚀"}
        # This shouldn't raise any exceptions
        emit("progress", data=complex_data)

    def test_api_queue_backpressure(self):
        print("  - Testing API Job Queue overflow handling...")
        
        import asyncio
        # Use a new loop for the test to avoid deprecation warnings or collisions
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        config = ScanRequest(target="backpressure.test")
        job = job_manager.create(config)
        job._queue = asyncio.Queue(maxsize=2)
        job._loop = loop
        
        # Push more events than the queue can hold
        for i in range(10):
            job.push_event({"type": "test", "val": i})
            
        self.assertEqual(len(job.events), 10)
        print(f"    Successfully handled {len(job.events)} events with queue cap at 2.")
        loop.close()

    def test_job_event_capping_integrity(self):
        print("  - Testing Event Cap (sliding window) integrity...")
        
        config = ScanRequest(target="cap.test")
        job = job_manager.create(config)
        job.EVENT_CAP = 5 # Force tiny cap for testing
        
        for i in range(10):
            job.push_event({"type": "log", "msg": f"Event {i}"})
            
        self.assertEqual(len(job.events), 5)
        self.assertEqual(job.events[0]["msg"], "Event 5")
        self.assertEqual(job.events[-1]["msg"], "Event 9")
        print("    Sliding window correctly maintained latest 5 events.")

if __name__ == "__main__":
    print("RUNNING ADVANCED INTEGRITY & STRESS TESTS\n")
    unittest.main()
