import sys, os, unittest
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.nvd_lookup import _parse_ver, _ver_lt, _ver_lte

class TestVersionEdgeCases(unittest.TestCase):
    def test_semantic_logic(self):
        # Standard semver
        self.assertTrue(_ver_lt("1.2.2", "1.2.3"))
        self.assertTrue(_ver_lt("1.2.3-rc1", "1.2.3"))
        self.assertTrue(_ver_lt("1.2.3-beta", "1.2.3-rc1"))
        self.assertTrue(_ver_lt("1.2.3-alpha", "1.2.3-beta"))
        
    def test_vendor_specific_formats(self):
        # OpenSSH style (8.9p1)
        self.assertTrue(_ver_lt("8.9", "8.9p1"))
        self.assertTrue(_ver_lt("8.9p1", "8.9p2"))
        
        # Patch suffixes
        self.assertTrue(_ver_lt("1.10", "1.10-patch1"))
        self.assertTrue(_ver_lt("1.10-patch1", "1.10-patch2"))
        
    def test_mismatched_lengths(self):
        self.assertTrue(_ver_lt("1.2", "1.2.1"))
        self.assertTrue(_ver_lt("1", "1.0.1"))
        
    def test_equality(self):
        self.assertTrue(_ver_lte("1.2.3", "1.2.3"))
        self.assertTrue(_ver_lte("1.2.3p1", "1.2.3p1"))

if __name__ == "__main__":
    unittest.main()
