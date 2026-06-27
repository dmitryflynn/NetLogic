"""Resource bounds on the ports field (dedup + length cap, anti-abuse)."""
import pytest

from api.models.scan_request import ScanRequest


def test_ports_deduplicated_and_normalized():
    assert ScanRequest(target="x.com", ports="custom=80,80,443,80,22").ports == "custom=80,443,22"
    assert ScanRequest(target="x.com", ports="80,443").ports == "custom=80,443"   # bare → canonical


def test_ports_presets_passthrough():
    assert ScanRequest(target="x.com", ports="quick").ports == "quick"
    assert ScanRequest(target="x.com", ports="full").ports == "full"


def test_ports_rejects_pathologically_long_input():
    with pytest.raises(ValueError):
        ScanRequest(target="x.com", ports="custom=" + ",".join(["80"] * 200_000))


def test_ports_rejects_out_of_range_and_nonnumeric():
    with pytest.raises(ValueError):
        ScanRequest(target="x.com", ports="custom=70000")
    with pytest.raises(ValueError):
        ScanRequest(target="x.com", ports="custom=80,abc")
