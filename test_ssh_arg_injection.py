"""
Security regression: ssh argument injection in authenticated scanning.

ssh parses any argv element starting with '-' as an option, so a crafted
ssh_user / ssh_key / host like '-oProxyCommand=<cmd>' would execute arbitrary
code on the SCANNING agent. Both layers must reject it:
  • the API request model (before a job is ever created), and
  • ssh_enumerate itself (covers the CLI path that bypasses pydantic).
"""
import pytest

from src.authenticated import ssh_enumerate, _rejects_option_injection


# ── ssh_enumerate (defense-in-depth, used by CLI + agent) ───────────────────────

@pytest.mark.parametrize("bad", [
    "-oProxyCommand=touch /tmp/pwned",
    "-Fxyz",
    "user name",          # whitespace
    "user\tname",
])
def test_enumerate_rejects_option_injection_in_user(bad):
    r = ssh_enumerate("10.0.0.5", bad)
    assert r.error and "unsafe characters" in r.error


def test_enumerate_rejects_option_injection_in_host():
    r = ssh_enumerate("-oProxyCommand=evil", "root")
    assert r.error and "unsafe characters" in r.error


def test_enumerate_rejects_option_injection_in_key_path():
    r = ssh_enumerate("10.0.0.5", "root", key_path="-oProxyCommand=evil")
    assert r.error and "unsafe characters" in r.error


def test_helper_allows_legitimate_values():
    assert not _rejects_option_injection("ubuntu")
    assert not _rejects_option_injection("10.0.0.5")
    assert not _rejects_option_injection("/home/me/.ssh/id_ed25519")
    assert not _rejects_option_injection("")          # empty = "not provided"


# ── API request model (rejects before a job is created) ─────────────────────────

def test_scan_request_rejects_malicious_ssh_user():
    from api.models.scan_request import ScanRequest
    with pytest.raises(ValueError):
        ScanRequest(target="example.com", ssh_user="-oProxyCommand=touch /tmp/x")


def test_scan_request_rejects_malicious_ssh_key():
    from api.models.scan_request import ScanRequest
    with pytest.raises(ValueError):
        ScanRequest(target="example.com", ssh_key="-oProxyCommand=evil")


def test_scan_request_accepts_legitimate_ssh_user():
    from api.models.scan_request import ScanRequest
    req = ScanRequest(target="example.com", ssh_user="ubuntu", ssh_key="/home/me/.ssh/id_rsa")
    assert req.ssh_user == "ubuntu"
