# NetLogic 🔍

**Attack Surface Mapper & Vulnerability Correlator**

NetLogic is a professional-grade network security reconnaissance tool that combines active port scanning, passive OSINT, live CVE correlation, SSL/TLS analysis, HTTP security auditing, WAF detection, DNS/email security assessment, and subdomain takeover detection into a single workflow — replacing what typically requires six or seven separate tools and hours of manual cross-referencing.

![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue)
![License: MIT](https://img.shields.io/badge/License-MIT-green)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)
![CVE Source: NVD](https://img.shields.io/badge/CVEs-NVD%20Live%20API-orange)

---

## What makes this different?

Most scanners stop at port discovery. NetLogic goes much further:

1. **Fingerprints** running services and extracts exact version strings via custom protocol probes (SSH, HTTP, FTP, Redis, MySQL, MongoDB…)
2. **Queries the live NIST NVD API** for CVEs matching every discovered version — no stale hardcoded database, always current
3. **Checks CISA KEV** (Known Exploited Vulnerabilities catalog) and flags actively exploited CVEs automatically
4. **Deep SSL/TLS analysis** — deprecated protocols, weak ciphers, POODLE/BEAST/CRIME/DROWN, certificate expiry, self-signed certs, hostname mismatch
5. **HTTP security header audit** — CSP, HSTS, X-Frame-Options, CORS misconfiguration, insecure cookies, server version disclosure
6. **Technology stack fingerprinting** — detects CMS (WordPress, Drupal, Joomla), frameworks, cloud provider (AWS/Azure/GCP), CDN, and WAF
7. **DNS/email security assessment** — SPF, DKIM, DMARC, DNSSEC, zone transfer attempts, CAA records, email spoofability score
8. **Subdomain takeover detection** — discovers subdomains via CT logs then checks 25+ providers (GitHub Pages, Heroku, S3, Netlify, Azure…) for dangling DNS
9. **Passive OSINT** without touching the target: Certificate Transparency logs, DNS enumeration (DoH), ASN/CIDR lookup
10. **Calculates composite risk scores** weighted by CVSS + CISA KEV exploit status
11. **Exports** machine-readable JSON (SIEM-ready), styled HTML reports, and rich terminal output

---

## Installation

```bash
git clone https://github.com/yourusername/netlogic.git
cd netlogic
# No third-party dependencies — pure Python 3.9+ standard library
python netlogic.py --version
```

---

## Usage

```bash
# Quick scan
python netlogic.py scanme.nmap.org

# Deep TLS + header audit
python netlogic.py example.com --tls --headers

# Full DNS/email security check
python netlogic.py example.com --dns

# Technology stack + WAF detection
python netlogic.py example.com --stack

# Subdomain takeover detection
python netlogic.py example.com --takeover

# Run everything at once
python netlogic.py example.com --full --report html --out ./reports

# CIDR block sweep (internal network audit)
python netlogic.py 192.168.1.0/24 --cidr --report json --out ./reports

# Custom port list
python netlogic.py 10.0.0.5 --ports custom=22,80,443,8080,9200 --timeout 3

# Only show HIGH+ CVEs
python netlogic.py example.com --min-cvss 7.0

# Use NVD API key for faster lookups
python netlogic.py example.com --nvd-key YOUR_KEY

# Cache management
python netlogic.py --cache-stats
python netlogic.py --clear-cache
python netlogic.py --preload-cache
```

---

## All Flags

| Flag | Description |
|---|---|
| `--ports quick\|full\|custom=...` | Port set to scan (default: quick) |
| `--tls` | Deep SSL/TLS analysis |
| `--headers` | HTTP security header audit |
| `--stack` | Technology stack + WAF fingerprinting |
| `--dns` | DNS/email security (SPF, DKIM, DMARC, DNSSEC) |
| `--takeover` | Subdomain takeover detection |
| `--osint` | Passive recon (DNS, CT logs, ASN) |
| `--full` | Run all of the above |
| `--report terminal\|json\|html\|all` | Output format |
| `--out <dir>` | Save reports to directory |
| `--cidr` | Treat target as CIDR block |
| `--min-cvss <score>` | Minimum CVSS score to report (default: 4.0) |
| `--nvd-key <key>` | NVD API key for faster rate limits |
| `--timeout <seconds>` | Per-port TCP timeout |
| `--threads <n>` | Max concurrent threads |
| `--cache-stats` | Show NVD cache info |
| `--clear-cache` | Clear NVD disk cache |
| `--preload-cache` | Pre-warm cache for 30+ common products |
| `--no-color` | Disable ANSI colors (for Windows CMD) |

---

## Example Output

```
======================================================================
  NetLogic Scan Report
  Target : scanme.nmap.org
  IP     : 45.33.32.156
  OS Est.: Linux/Unix
  Runtime: 4.2s
======================================================================

  OPEN PORTS
  PORT     SERVICE          PRODUCT/VERSION                     TLS
  22       ssh              OpenSSH 6.6.1p1 Ubuntu              -
  80       http             Apache/2.4.7                        -
  443      https                                                TLS

  VULNERABILITY FINDINGS  (via NVD live API)

  Port 22/ssh (OpenSSH 6.6.1p1)
  Risk Score: 9.8/10

    CRITICAL  CVE-2023-38408  CVSS 9.8  * CISA KEV
    OpenSSH < 9.3p2 ssh-agent RCE via PKCS#11 — exploitable with agent forwarding.
    Actively exploited — in CISA Known Exploited Vulnerabilities catalog
    Affects: >= 1.0, < 9.3p2
    Ref: https://nvd.nist.gov/vuln/detail/CVE-2023-38408

    HIGH  CVE-2018-15473  CVSS 5.3
    OpenSSH < 7.7 username enumeration via timing side-channel.

  SSL/TLS ANALYSIS
  Port 443 - Grade: C
  Protocols : TLSv1.3, TLSv1.2, TLSv1.1
  Deprecated: TLSv1.1
    MEDIUM  Deprecated Protocol Supported: TLSv1.1

  HTTP SECURITY HEADERS - Score: 45/100  Grade: F
  Missing: strict-transport-security, content-security-policy, x-frame-options
    HIGH  Missing HSTS Header
    HIGH  Missing Content-Security-Policy

  DNS & EMAIL SECURITY - Spoofability: 7/10 (SPOOFABLE)
  SPF    - MISSING - anyone can spoof this domain
  DKIM   - No selectors found
  DMARC  - MISSING - no policy enforcement
    HIGH  Domain Spoofable via Email (Score: 7/10)
```

---

## Architecture

```
netlogic/
├── netlogic.py               <- CLI entry point, flag routing, output orchestration
└── src/
    ├── scanner.py             <- TCP port scanner, service prober, banner grabber
    ├── cve_correlator.py      <- NVD-powered CVE correlation, offline fallback
    ├── nvd_lookup.py          <- Live NIST NVD API v2.0 client, disk cache, CISA KEV
    ├── osint.py               <- DNS/DoH, CT logs (crt.sh), ASN lookup, HTTP fingerprint
    ├── tls_analyzer.py        <- SSL/TLS deep analysis, POODLE/BEAST/CRIME detection
    ├── header_audit.py        <- HTTP security header audit, CORS, cookie flags
    ├── stack_fingerprint.py   <- CMS, framework, cloud, CDN, WAF detection
    ├── dns_security.py        <- SPF, DKIM, DMARC, DNSSEC, zone transfer, spoofability
    ├── takeover.py            <- Subdomain takeover detection (25+ providers)
    ├── reporter.py            <- Terminal (ANSI), JSON, and HTML report generators
    └── json_bridge.py         <- Streaming JSON event emitter for Electron desktop app
```

### Scanner Engine (`scanner.py`)
- Concurrent TCP connect scanning via `ThreadPoolExecutor` (up to 100 threads)
- Per-service protocol probes: HTTP GET, Redis INFO, MongoDB wire protocol, MySQL handshake, and more
- Banner parsing with regex version extraction for 15+ services
- TLS handshake inspection + certificate CN extraction
- TTL-based OS fingerprinting (Linux / Windows / Network Device)

### CVE Correlator (`cve_correlator.py`) + NVD Lookup (`nvd_lookup.py`)
- **Live NIST NVD API v2.0** queries for every discovered product/version — never outdated
- **CISA KEV integration** — flags CVEs actively exploited in the wild with a star marker
- **Disk cache** at `~/.netlogic/nvd_cache/` — 24-hour TTL, instant on repeat scans
- **Offline fallback** — 25 critical hardcoded signatures used if NVD is unreachable
- Semantic version range filtering — only returns CVEs that apply to the exact version found
- Composite risk scoring: CVSS base + KEV bonus + breadth of findings
- Optional API key (`--nvd-key` or `NETLOGIC_NVD_KEY` env var) for 10x faster queries

### SSL/TLS Analyzer (`tls_analyzer.py`)
- Protocol version probing: TLSv1.0, TLSv1.1, TLSv1.2, TLSv1.3
- Cipher suite weakness detection: RC4, DES, 3DES, NULL, EXPORT, Anonymous DH
- Known vulnerability checks: POODLE (CVE-2014-3566), BEAST (CVE-2011-3389), CRIME (CVE-2012-4929), DROWN (CVE-2016-0800)
- Certificate analysis: expiry, self-signed, hostname mismatch, SAN coverage
- Letter grading: A through F based on findings

### HTTP Header Auditor (`header_audit.py`)
- Checks 10+ security headers: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, CORP, COEP
- CORS misconfiguration detection (wildcard + credentials = CRITICAL)
- Cookie flag analysis: Secure, HttpOnly, SameSite per cookie
- Server/X-Powered-By version disclosure detection
- Scored 0–100 with letter grade

### Stack Fingerprinter (`stack_fingerprint.py`)
- CMS detection: WordPress (+ deep scan of login, REST API, xmlrpc.php), Drupal, Joomla, Shopify, Ghost, Squarespace, Wix, Webflow
- Framework detection: Next.js, Nuxt, Angular, React, Vue, Laravel, Django, Rails, Flask
- Cloud/CDN: AWS, Azure, GCP, Cloudflare, Fastly, Akamai, Vercel, Netlify
- WAF detection: Cloudflare WAF, AWS WAF, Imperva, Akamai, Sucuri, ModSecurity, F5 BIG-IP, Wordfence, Barracuda — with bypass notes per product
- Detection methods: response headers, HTML body, cookies, and active probing with malicious payloads

### DNS Security Checker (`dns_security.py`)
- **SPF**: presence, `all` mechanism strength, DNS lookup count (RFC 7208 limit of 10)
- **DKIM**: probes 25 common selectors, checks key length
- **DMARC**: policy enforcement level (`none`/`quarantine`/`reject`), subdomain policy, reporting addresses
- **DNSSEC**: DS and DNSKEY record verification
- **CAA**: certificate authority authorization records
- **Zone Transfer**: raw AXFR attempt against all nameservers
- **Wildcard DNS**: detects `*.domain` resolution (subdomain takeover risk multiplier)
- **Email spoofability score**: 0–10 composite rating based on SPF + DKIM + DMARC posture

### Subdomain Takeover Detector (`takeover.py`)
- Discovers subdomains via Certificate Transparency logs (crt.sh)
- Follows full CNAME chains via Cloudflare DoH
- Fingerprint database for 25+ providers: GitHub Pages, Heroku, Amazon S3, CloudFront, Netlify, Vercel, Azure, Shopify, Fastly, Ghost, Tumblr, WordPress.com, Zendesk, Surge.sh, Webflow, Squarespace, Wix, ReadTheDocs, Bitbucket, and more
- HIGH confidence: CNAME matches provider + response body matches takeover fingerprint
- MEDIUM confidence: CNAME matches provider OR NXDOMAIN dangling record

### OSINT Module (`osint.py`)
- All queries use public APIs — zero direct contact with target
- `crt.sh` Certificate Transparency subdomain enumeration (up to 100 subdomains)
- Cloudflare DoH for DNS records: A, AAAA, MX, TXT, NS, CNAME, SOA, SRV
- `ipinfo.io` for ASN/org/country lookup
- HTTP header technology fingerprinting

### Reporter (`reporter.py`)
- **Terminal**: color-coded severity badges, aligned tables, per-CVE detail with version ranges, CWE IDs, and references
- **JSON**: structured schema compatible with Elastic SIEM / Splunk, embeds TLS/header/DNS/takeover results
- **HTML**: dark-themed professional report with stat cards and sortable tables

### Electron Desktop App (`json_bridge.py` + `electron/`)
- Streams scan results live to GUI via newline-delimited JSON events
- Events: `port`, `vuln`, `osint`, `progress`, `done`, `error`
- Built with Electron + custom frameless window, system tray support
- Distributable as Windows installer via PyInstaller + NSIS (`build.bat`)

---

## CVE Coverage

| Service | Vulnerability Classes |
|---|---|
| OpenSSH | RCE via ssh-agent (KEV), priv-esc, username enumeration, scp injection |
| Apache HTTPD | Path traversal + RCE (Metasploit), request smuggling, mod_proxy SSRF |
| nginx | HTTP/2 Rapid Reset DoS, DNS resolver heap overwrite, mp4 memory corruption |
| Microsoft IIS | Wormable HTTP stack RCE, WebDAV buffer overflow (Metasploit) |
| PHP | FPM path_info RCE, password_verify overflow, unserialize injection |
| WordPress | PHP object injection RCE, SQL injection, REST API user enumeration |
| Drupal | Drupalgeddon2 unauthenticated RCE (Metasploit), REST API object injection |
| Joomla | Unauthenticated config read via REST API |
| Apache Tomcat | Ghostcat AJP file inclusion + RCE |
| Spring Framework | Spring4Shell RCE via data binding (Metasploit) |
| Log4j | Log4Shell JNDI injection (CVE-2021-44228, CVSS 10.0) |
| Redis | Lua sandbox escape RCE, integer overflow RCE |
| vsftpd | Backdoor shell on 2.3.4 — bind shell port 6200 (Metasploit) |
| ProFTPD | Unauthenticated file copy via mod_copy |
| PostgreSQL | Privilege escalation via autovacuum |
| MySQL / MariaDB | DoS, use-after-free |
| MongoDB | Unauthenticated access, MITM via cert validation bypass |
| Elasticsearch | Data exposure, unauthenticated API access |
| Memcached | UDP DRDoS amplification (50,000x amplification factor) |
| Samba | Out-of-bounds heap write RCE via VFS fruit module |
| OpenSSL | Heartbleed memory disclosure, X.400 ASN.1 type confusion |
| Docker daemon | Socket exposure, container escape |
| Kubernetes API | Privilege escalation |
| Exim | Local privilege escalation via /tmp race condition |
| + any product | Live NVD API fallback — searches NIST for any product/version not listed above |

---

## Legal Notice

> **NetLogic is intended for authorized security assessments, penetration testing, and network administration only.**
> Scanning hosts without explicit written permission is illegal in most jurisdictions.
> The author assumes no liability for unauthorized use.

---

## License

MIT © 2026 Dmitry Flynn — See [LICENSE](LICENSE)
