"""
NetLogic - DNS Security Checker
Comprehensive email and DNS security posture assessment.

Checks:
  SPF   — Sender Policy Framework (email spoofing prevention)
  DKIM  — DomainKeys Identified Mail (cryptographic email signing)
  DMARC — Domain-based Message Authentication (policy enforcement)
  DNSSEC — DNS Security Extensions (DNS tampering prevention)
  MX    — Mail server security and exposure
  Zone Transfer — AXFR attempt (information disclosure)
  CAA   — Certificate Authority Authorization
  Subdomain wildcard DNS
  Email spoofability score
"""

import socket
import json
import urllib.request
import urllib.parse
import re
from dataclasses import dataclass, field
from typing import Optional
import concurrent.futures


@dataclass
class AuditFinding:
    title: str
    description: str
    remediation: str
    severity: str  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    category: str  # DNS, SPF, DMARC, etc.

# ─── Data Models ────────────────────────────────────────────────────────────────

@dataclass
class SPFResult:
    present: bool = False
    record: str = ""
    valid: bool = False
    mechanism_count: int = 0
    all_mechanism: str = ""    # +all / -all / ~all / ?all
    includes: list[str] = field(default_factory=list)
    findings: list[AuditFinding] = field(default_factory=list)

@dataclass
class DKIMResult:
    checked_selectors: list[str] = field(default_factory=list)
    found_selectors: list[str] = field(default_factory=list)
    records: dict = field(default_factory=dict)
    findings: list[AuditFinding] = field(default_factory=list)

@dataclass
class DMARCResult:
    present: bool = False
    record: str = ""
    policy: str = ""        # none / quarantine / reject
    subdomain_policy: str = ""
    pct: int = 100
    rua: list[str] = field(default_factory=list)
    ruf: list[str] = field(default_factory=list)
    findings: list[AuditFinding] = field(default_factory=list)

@dataclass
class MXRecord:
    priority: int
    host: str
    ip: Optional[str] = None
    provider: Optional[str] = None

@dataclass
class DNSSecResult:
    enabled: bool = False
    ds_records: list[str] = field(default_factory=list)
    dnskey_found: bool = False
    issues: list[str] = field(default_factory=list)

@dataclass
class CAAResult:
    present: bool = False
    records: list[str] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)

@dataclass
class DNSSecurityResult:
    domain: str
    spf: SPFResult = field(default_factory=SPFResult)
    dkim: DKIMResult = field(default_factory=DKIMResult)
    dmarc: DMARCResult = field(default_factory=DMARCResult)
    mx_records: list[MXRecord] = field(default_factory=list)
    dnssec: DNSSecResult = field(default_factory=DNSSecResult)
    caa: CAAResult = field(default_factory=CAAResult)
    zone_transfer_vulnerable: bool = False
    zone_transfer_data: list[str] = field(default_factory=list)
    wildcard_dns: bool = False
    email_spoofable: bool = False
    spoofability_score: int = 0    # 0 (safe) to 10 (fully spoofable)
    findings: list[dict] = field(default_factory=list)


# ─── DNS-over-HTTPS Query ────────────────────────────────────────────────────

def _doh(name: str, rtype: str) -> list[dict]:
    """Query Cloudflare DoH. Returns list of answer dicts."""
    url = f"https://cloudflare-dns.com/dns-query?name={urllib.parse.quote(name)}&type={rtype}"
    try:
        req = urllib.request.Request(url, headers={
            "Accept": "application/dns-json",
            "User-Agent": "NetLogic/2.0",
        })
        with urllib.request.urlopen(req, timeout=6) as resp:
            data = json.loads(resp.read())
        return data.get("Answer", [])
    except Exception:
        return []

def _txt_records(name: str) -> list[str]:
    answers = _doh(name, "TXT")
    results = []
    for a in answers:
        val = a.get("data", "").strip('"')
        # DoH may split long TXT records with spaces and quotes
        val = re.sub(r'"\s+"', "", val)
        results.append(val)
    return results

def _mx_records(domain: str) -> list[tuple[int, str]]:
    answers = _doh(domain, "MX")
    results = []
    for a in answers:
        data = a.get("data", "")
        parts = data.split()
        if len(parts) == 2:
            try:
                results.append((int(parts[0]), parts[1].rstrip(".")))
            except ValueError:
                pass
    return sorted(results)

def _ns_records(domain: str) -> list[str]:
    answers = _doh(domain, "NS")
    return [a.get("data", "").rstrip(".") for a in answers]


# ─── SPF Analysis ─────────────────────────────────────────────────────────────

def check_spf(domain: str) -> SPFResult:
    result = SPFResult()
    txts = _txt_records(domain)
    spf_records = [t for t in txts if t.startswith("v=spf1")]

    if not spf_records:
        result.findings.append(AuditFinding(
            title="Missing SPF Record",
            description="The domain lacks an SPF record, allowing unauthorized servers to send email on its behalf.",
            remediation="Implement a v=spf1 record. Example: v=spf1 include:_spf.google.com ~all",
            severity="HIGH",
            category="SPF"
        ))
        return result

    if len(spf_records) > 1:
        result.findings.append(AuditFinding(
            title="Multiple SPF Records",
            description=f"Multiple SPF records ({len(spf_records)}) found. Only one record is allowed; multiple records cause validation to fail.",
            remediation="Merge your SPF records into a single v=spf1 record.",
            severity="HIGH",
            category="SPF"
        ))

    result.present = True
    result.record = spf_records[0]

    # Parse mechanisms
    parts = result.record.split()
    mechanisms = [p for p in parts if not p.startswith("v=")]
    result.mechanism_count = len(mechanisms)

    # Check 'all' mechanism
    all_mech = next((p for p in parts if p.endswith("all")), None)
    result.all_mechanism = all_mech or ""

    if not all_mech:
        result.findings.append(AuditFinding(
            title="Missing SPF All Mechanism",
            description="The SPF record lacks an 'all' mechanism, leaving behavior for unlisted senders undefined.",
            remediation="Add ~all or -all to the end of the record.",
            severity="MEDIUM",
            category="SPF"
        ))
    elif all_mech in ("+all", "all"):
        result.findings.append(AuditFinding(
            title="Insecure SPF All Policy",
            description=f"Policy '{all_mech}' explicitly permits EVERY server on the internet to send as this domain.",
            remediation="Replace +all with -all (fail) or ~all (softfail).",
            severity="CRITICAL",
            category="SPF"
        ))
        result.valid = False
    elif all_mech == "?all":
        result.findings.append(AuditFinding(
            title="Neutral SPF Policy",
            description="Policy '?all' provides no instruction to receiving servers, offering no protection against spoofing.",
            remediation="Use -all or ~all for policy enforcement.",
            severity="MEDIUM",
            category="SPF"
        ))
    elif all_mech == "~all":
        result.findings.append(AuditFinding(
            title="Weak SPF Policy (Softfail)",
            description="The domain uses a softfail policy (~all), which asks servers to accept but mark suspicious mail. Spoofed mail may still reach users.",
            remediation="Switch to a hard fail policy (-all) for maximum protection.",
            severity="LOW",
            category="SPF"
        ))
        result.valid = True   # Accepted by many analysts but technically weak
    elif all_mech == "-all":
        result.valid = True   # Correct

    # DNS lookup count (RFC limit: 10)
    includes = re.findall(r"include:(\S+)", result.record)
    result.includes = includes
    lookup_count = len([p for p in parts if p.startswith(("include:", "a:", "mx:", "exists:", "redirect="))])
    if lookup_count > 10:
        result.findings.append(AuditFinding(
            title="Excessive SPF Lookups",
            description=f"SPF record triggers {lookup_count} DNS lookups, exceeding the RFC 7208 limit of 10. Servers may ignore the record.",
            remediation="Flatten your SPF record or use SPF mechanisms like 'ip4' to reduce external lookups.",
            severity="HIGH",
            category="SPF"
        ))

    # ptr mechanism deprecated
    if "ptr" in result.record:
        result.findings.append(AuditFinding(
            title="Deprecated SPF PTR Mechanism",
            description="The 'ptr' mechanism is deprecated and inefficient. Many mail servers ignore it.",
            remediation="Remove the 'ptr' mechanism and replace it with 'a' or 'mx' if needed.",
            severity="LOW",
            category="SPF"
        ))

    return result


# ─── DKIM Analysis ────────────────────────────────────────────────────────────

COMMON_DKIM_SELECTORS = [
    "default", "google", "mail", "dkim", "k1", "k2", "s1", "s2",
    "selector1", "selector2", "email", "mailjet", "sendgrid",
    "mandrill", "smtp", "mta", "mx", "postmaster", "marketing",
    "newsletter", "em", "em1", "em2", "key1", "key2",
]

def check_dkim(domain: str) -> DKIMResult:
    result = DKIMResult()
    result.checked_selectors = COMMON_DKIM_SELECTORS.copy()

    def probe_selector(sel):
        dkim_domain = f"{sel}._domainkey.{domain}"
        answers = _doh(dkim_domain, "TXT")
        for a in answers:
            val = a.get("data", "")
            if "v=DKIM1" in val or "p=" in val:
                return sel, val
        return None, None

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as exe:
        futures = [exe.submit(probe_selector, sel) for sel in COMMON_DKIM_SELECTORS]
        for f in concurrent.futures.as_completed(futures):
            sel, record = f.result()
            if sel:
                result.found_selectors.append(sel)
                result.records[sel] = record

                # Check key length
                p_match = re.search(r"p=([A-Za-z0-9+/=]+)", record or "")
                if p_match:
                    key_b64 = p_match.group(1)
                    key_len = len(key_b64) * 6 // 8 * 8  # rough bit estimate
                    if key_len < 1024:
                        result.findings.append(AuditFinding(
                            title="Weak DKIM Key Length",
                            description=f"Selector '{sel}': RSA key appears short (<1024 bits) — vulnerable to factoring",
                            remediation="Generate a new 2048-bit or larger RSA key pair for DKIM signing.",
                            severity="HIGH",
                            category="DKIM",
                        ))

                # Empty p= means key revoked
                if "p=" in (record or "") and re.search(r"p=\s*;|p=\"\"", record or ""):
                    result.findings.append(AuditFinding(
                        title="Revoked DKIM Key",
                        description=f"Selector '{sel}': public key is empty (revoked)",
                        remediation="Configure a new DKIM selector with a valid key, or remove unused selectors.",
                        severity="HIGH",
                        category="DKIM",
                    ))

    if not result.found_selectors:
        result.findings.append(AuditFinding(
            title="No DKIM Selectors Found",
            description="No DKIM selectors found from common list — DKIM may not be configured",
            remediation="Configure DKIM signing with your mail provider and publish the public key in DNS.",
            severity="MEDIUM",
            category="DKIM",
        ))

    return result


# ─── DMARC Analysis ──────────────────────────────────────────────────────────

def check_dmarc(domain: str) -> DMARCResult:
    result = DMARCResult()
    txts = _txt_records(f"_dmarc.{domain}")
    dmarc_records = [t for t in txts if t.startswith("v=DMARC1")]

    if not dmarc_records:
        # Check organizational domain
        parts = domain.split(".")
        if len(parts) > 2:
            org = ".".join(parts[-2:])
            txts2 = _txt_records(f"_dmarc.{org}")
            dmarc_records = [t for t in txts2 if t.startswith("v=DMARC1")]

    if not dmarc_records:
        result.findings.append(AuditFinding(
            title="Missing DMARC Record",
            description="The domain lacks a DMARC policy, allowing attackers to spoof its identity without consequence.",
            remediation="Implement a DMARC record: v=DMARC1; p=quarantine; rua=mailto:admin@domain.com",
            severity="HIGH",
            category="DMARC"
        ))
        return result

    result.present = True
    result.record = dmarc_records[0]

    # Parse tags
    tags = dict(re.findall(r"(\w+)=([^;]+)", result.record))

    result.policy = tags.get("p", "none").strip()
    result.subdomain_policy = tags.get("sp", result.policy).strip()
    try:
        result.pct = int(tags.get("pct", "100").strip())
    except ValueError:
        result.pct = 100
        result.findings.append(AuditFinding(
            title="Invalid DMARC pct Tag",
            description="The pct= tag contains a non-integer value. Defaulting to 100%.",
            remediation="Use an integer between 0 and 100 for the pct tag.",
            severity="LOW",
            category="DMARC"
        ))

    rua = tags.get("rua", "")
    result.rua = [r.strip() for r in rua.split(",") if r.strip()]
    ruf = tags.get("ruf", "")
    result.ruf = [r.strip() for r in ruf.split(",") if r.strip()]

    # Policy checks
    if result.policy in ("quarantine", "reject"):
        result.valid = True

    if result.policy == "none":
        result.findings.append(AuditFinding(
            title="DMARC Policy is 'None'",
            description="Policy 'p=none' is for monitoring only and does not block spoofed emails. Attacks will still be delivered.",
            remediation="Transition to 'p=quarantine' or 'p=reject' to enforce security.",
            severity="HIGH",
            category="DMARC"
        ))
    elif result.policy == "quarantine":
        result.findings.append(AuditFinding(
            title="DMARC Policy is 'Quarantine'",
            description=f"Policy 'p=quarantine' directs spoofed mail to recipients' spam folders but does not outright reject them.",
            remediation="Consider moving to 'p=reject' to fully block unauthorized mail.",
            severity="LOW",
            category="DMARC"
        ))

    if result.pct < 100:
        result.findings.append(AuditFinding(
            title="DMARC Percentage is Reduced",
            description=f"Only {result.pct}% of emails are subject to the DMARC policy. This allows some spoofing bypass.",
            remediation="Increase pct= to 100 for full policy enforcement.",
            severity="MEDIUM",
            category="DMARC"
        ))

    if result.subdomain_policy == "none" and result.policy != "none":
        result.findings.append(AuditFinding(
            title="Weak DMARC Subdomain Policy",
            description=f"Policy sp=none permits attackers to spoof subdomains even if the main domain is protected.",
            remediation="Set sp= to match the main domain policy (sp=quarantine or sp=reject).",
            severity="HIGH",
            category="DMARC"
        ))

    if not result.rua:
        result.findings.append(AuditFinding(
            title="Missing DMARC Reporting (RUA)",
            description="DMARC record does not list a rua= address. You will not receive reports on spoofing attempts.",
            remediation="Add an aggregate reporting email: rua=mailto:dmarc-reports@domain.com.",
            severity="MEDIUM",
            category="DMARC"
        ))

    return result


# ─── MX Analysis ─────────────────────────────────────────────────────────────

MX_PROVIDERS = {
    r"google\.com|googlemail\.com|gmail\.com": "Google Workspace",
    r"outlook\.com|hotmail\.com|microsoft\.com": "Microsoft 365",
    r"mimecast\.com": "Mimecast",
    r"proofpoint\.com": "Proofpoint",
    r"barracuda\.com": "Barracuda",
    r"messagelabs\.com|symantec": "Symantec/Broadcom",
    r"mailgun\.org": "Mailgun",
    r"sendgrid\.net": "SendGrid",
    r"amazonses\.com": "Amazon SES",
    r"pphosted\.com": "Proofpoint Hosted",
    r"protection\.outlook\.com": "Exchange Online Protection",
}

def check_mx(domain: str) -> list[MXRecord]:
    mx_raw = _mx_records(domain)
    results = []
    for priority, host in mx_raw:
        ip = None
        try:
            ip = socket.gethostbyname(host)
        except Exception:
            pass
        provider = None
        for pattern, name in MX_PROVIDERS.items():
            if re.search(pattern, host, re.IGNORECASE):
                provider = name
                break
        results.append(MXRecord(priority=priority, host=host, ip=ip, provider=provider))
    return results


# ─── Zone Transfer ────────────────────────────────────────────────────────────

def check_zone_transfer(domain: str) -> tuple[bool, list[str]]:
    """Attempt AXFR zone transfer against all NS records."""
    ns_list = _ns_records(domain)
    records = []

    for ns in ns_list[:3]:   # Limit to first 3 nameservers
        try:
            ip = socket.gethostbyname(ns)
            # Raw TCP DNS AXFR request
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(5)
                sock.connect((ip, 53))

                # Build AXFR query
                import struct
                query_id = b'\xaa\xbb'
                flags = b'\x00\x00'
                qdcount = b'\x00\x01'
                ancount = b'\x00\x00'
                nscount = b'\x00\x00'
                arcount = b'\x00\x00'
                header = query_id + flags + qdcount + ancount + nscount + arcount

                # Encode domain name
                qname = b""
                for label in domain.split("."):
                    qname += bytes([len(label)]) + label.encode()
                qname += b"\x00"

                qtype = b'\x00\xfc'   # AXFR
                qclass = b'\x00\x01'  # IN

                query = header + qname + qtype + qclass
                length_prefix = struct.pack(">H", len(query))
                sock.sendall(length_prefix + query)

                response = sock.recv(4096)

            # TCP DNS: 2-byte length prefix, then 12-byte DNS header.
            # Bytes 8-9 (offset 8) = ANCOUNT, bytes 10-11 = NSCOUNT, byte 5 low nibble = RCODE.
            if len(response) >= 14:
                rcode = response[5] & 0x0F
                ancount = struct.unpack(">H", response[8:10])[0]
                nscount = struct.unpack(">H", response[10:12])[0]
                if rcode == 0 and (ancount + nscount) > 5:
                    records.append(f"Vulnerable to zone transfer via {ns} ({ip}) — {ancount} records returned")
                    return True, records
        except Exception:
            pass

    return False, []


# ─── DNSSEC ──────────────────────────────────────────────────────────────────

def check_dnssec(domain: str) -> DNSSecResult:
    result = DNSSecResult()

    # Check for DS records (indicates DNSSEC delegation)
    ds = _doh(domain, "DS")
    if ds:
        result.enabled = True
        result.ds_records = [a.get("data", "") for a in ds]

    # Check for DNSKEY
    dnskey = _doh(domain, "DNSKEY")
    if dnskey:
        result.dnskey_found = True
        result.enabled = True

    if not result.enabled:
        result.issues.append(
            "DNSSEC not enabled — DNS responses can be forged (DNS cache poisoning, BGP hijacking)"
        )

    return result


# ─── CAA Records ─────────────────────────────────────────────────────────────

def check_caa(domain: str) -> CAAResult:
    result = CAAResult()
    answers = _doh(domain, "CAA")

    if not answers:
        result.issues.append(
            "No CAA records — any Certificate Authority can issue TLS certs for this domain. "
            "CAA records restrict which CAs are authorized."
        )
        return result

    result.present = True
    result.records = [a.get("data", "") for a in answers]

    # Check for issuewild restriction
    has_issuewild = any("issuewild" in r for r in result.records)
    if not has_issuewild:
        result.issues.append("No 'issuewild' CAA tag — wildcard certs can be issued by any authorized CA")

    return result


# ─── Wildcard DNS ─────────────────────────────────────────────────────────────

def check_wildcard_dns(domain: str) -> bool:
    """Check if *.domain resolves (wildcard DNS — major subdomain takeover risk)."""
    test_host = f"this-should-not-exist-{hash(domain) % 99999}.{domain}"
    # Use DoH for consistency — avoids local resolver caching and VPN/split-horizon issues
    answers = _doh(test_host, "A")
    return bool(answers)


# ─── Spoofability Scoring ────────────────────────────────────────────────────

def calculate_spoofability(spf: SPFResult, dkim: DKIMResult, dmarc: DMARCResult) -> tuple[bool, int]:
    """
    Score 0-10 for how easily this domain can be spoofed in email.
    10 = trivially spoofable, 0 = well-protected.
    """
    score = 0

    # SPF
    if not spf.present:
        score += 4
    elif spf.all_mechanism in ("+all", "?all", ""):
        score += 3
    elif spf.all_mechanism == "~all":
        score += 1

    # DMARC
    if not dmarc.present:
        score += 4
    elif dmarc.policy == "none":
        score += 3
    elif dmarc.policy == "quarantine":
        score += 1

    # DKIM
    if not dkim.found_selectors:
        score += 2

    spoofable = score >= 5
    return spoofable, min(score, 10)


# ─── Finding Builder ─────────────────────────────────────────────────────────

def _finding(severity, title, detail, recommendation=""):
    return {"severity": severity, "title": title, "detail": detail, "recommendation": recommendation}


# ─── Main Orchestrator ───────────────────────────────────────────────────────

def check_dns_security(domain: str) -> DNSSecurityResult:
    result = DNSSecurityResult(domain=domain)

    # Run all checks concurrently
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as exe:
        f_spf      = exe.submit(check_spf, domain)
        f_dkim     = exe.submit(check_dkim, domain)
        f_dmarc    = exe.submit(check_dmarc, domain)
        f_mx       = exe.submit(check_mx, domain)
        f_dnssec   = exe.submit(check_dnssec, domain)
        f_caa      = exe.submit(check_caa, domain)
        f_zone     = exe.submit(check_zone_transfer, domain)
        f_wildcard = exe.submit(check_wildcard_dns, domain)

        result.spf      = f_spf.result()
        result.dkim     = f_dkim.result()
        result.dmarc    = f_dmarc.result()
        result.mx_records = f_mx.result()
        result.dnssec   = f_dnssec.result()
        result.caa      = f_caa.result()
        result.zone_transfer_vulnerable, result.zone_transfer_data = f_zone.result()
        result.wildcard_dns = f_wildcard.result()

    # Spoofability
    result.email_spoofable, result.spoofability_score = calculate_spoofability(
        result.spf, result.dkim, result.dmarc
    )

    # Build findings list
    if not result.spf.present:
        result.findings.append(_finding(
            "HIGH", "Missing SPF Record",
            "No SPF record found. Anyone can send emails appearing to come from this domain.",
            f"Add TXT record: v=spf1 include:_spf.google.com -all"
        ))
    elif result.spf.findings:
        for finding in result.spf.findings:
            result.findings.append(_finding(
                finding.severity, finding.title, finding.description,
                finding.remediation,
            ))

    if not result.dkim.found_selectors:
        result.findings.append(_finding(
            "MEDIUM", "No DKIM Selectors Found",
            "DKIM signing not detected. Emails cannot be cryptographically verified.",
            "Configure DKIM signing with your mail provider and publish the public key in DNS."
        ))

    if not result.dmarc.present:
        result.findings.append(_finding(
            "HIGH", "Missing DMARC Record",
            "No DMARC policy. SPF/DKIM failures are not enforced — spoofed emails may be delivered.",
            "Add: _dmarc.domain TXT v=DMARC1; p=reject; rua=mailto:dmarc@domain.com"
        ))
    elif result.dmarc.policy == "none":
        result.findings.append(_finding(
            "MEDIUM", "DMARC Policy: none (No Enforcement)",
            "DMARC is monitoring only. Spoofed emails are still delivered to inboxes.",
            "Change p=none to p=quarantine or p=reject after reviewing reports."
        ))

    if result.zone_transfer_vulnerable:
        result.findings.append(_finding(
            "CRITICAL", "Zone Transfer (AXFR) Allowed",
            "DNS zone transfer succeeded — full list of DNS records disclosed to any requester. "
            "Reveals internal hostnames, IPs, mail servers, and infrastructure layout.",
            "Restrict AXFR to authorized secondary nameservers only."
        ))

    if result.wildcard_dns:
        result.findings.append(_finding(
            "MEDIUM", "Wildcard DNS Configured",
            "*.domain resolves — any subdomain points somewhere. "
            "Increases subdomain takeover attack surface significantly.",
            "Remove wildcard DNS unless intentionally required."
        ))

    if not result.dnssec.enabled:
        result.findings.append(_finding(
            "LOW", "DNSSEC Not Enabled",
            "DNS responses can be forged without DNSSEC. Enables DNS cache poisoning attacks.",
            "Enable DNSSEC at your domain registrar and DNS provider."
        ))

    if not result.caa.present:
        result.findings.append(_finding(
            "LOW", "No CAA Records",
            "Any trusted CA can issue certificates for this domain.",
            'Add: domain CAA 0 issue "letsencrypt.org"'
        ))

    if result.email_spoofable:
        result.findings.append(_finding(
            "HIGH",
            f"Domain Spoofable via Email (Score: {result.spoofability_score}/10)",
            "Combination of weak/missing SPF, DKIM, and DMARC means this domain "
            "can be used in phishing and business email compromise (BEC) attacks.",
            "Implement SPF with -all, configure DKIM, set DMARC to p=reject."
        ))

    return result