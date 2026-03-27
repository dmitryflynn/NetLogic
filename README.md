# NetLogic

**Attack Surface Mapper & Vulnerability Correlator**

NetLogic is a professional-grade network security reconnaissance tool that combines active port scanning, service misconfiguration detection, passive OSINT, live CVE correlation, SSL/TLS analysis, HTTP security auditing, WAF detection, DNS/email security assessment, subdomain takeover detection, and active CVE-specific probing into a single workflow — replacing what typically requires eight or more separate tools and hours of manual cross-referencing.

[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green)](https://github.com/dmitryflynn/netlogic/blob/main/LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)](https://github.com/dmitryflynn/netlogic)
[![CVE Source: NVD](https://img.shields.io/badge/CVEs-NVD%20Live%20API-orange)](https://nvd.nist.gov/)
[![View on GitHub](https://img.shields.io/badge/GitHub-dmitryflynn%2Fnetlogic-181717?logo=github)](https://github.com/dmitryflynn/netlogic)

> **Python CLI:** Zero third-party dependencies — pure Python 3.9+ standard library.
> **Electron GUI:** Requires Node.js; uses `electron-store` for settings persistence.

---

## What makes this different?

Most scanners stop at port discovery. NetLogic goes further:

1. **Fingerprints** running services and extracts exact version strings via 22 custom protocol probes across 43 mapped port/service combinations (SSH, HTTP, FTP, Redis, MySQL, MongoDB, Docker, Kubernetes, etcd, Vault, and more)
2. **Queries the live NIST NVD API** for CVEs matching every discovered product/version across 101 product keyword mappings — no stale hardcoded database, always current
3. **Checks CISA KEV** (Known Exploited Vulnerabilities catalog) and flags actively exploited CVEs automatically
4. **Flags exploit availability** with tiered indicators: Metasploit module (52 CVEs tracked), public PoC (88 CVEs tracked), or CISA KEV
5. **Active service probing** — detects unauthenticated access to Redis, MongoDB, Elasticsearch, CouchDB, etcd, Consul, Docker API, Kubernetes API, Vault, Prometheus, RabbitMQ, InfluxDB, FTP; probes 33 HTTP admin panel paths
6. **CVE-specific active confirmation probes** — safely confirms Apache CVE-2021-41773/42013 path traversal, Grafana CVE-2021-43798, Shellshock, Ghostcat AJP, Spring Boot actuator exposure, open redirect, directory traversal, exposed backup files with credentials, and more
7. **Deep SSL/TLS analysis** — deprecated protocols, weak ciphers, POODLE/BEAST/CRIME/DROWN, certificate expiry, self-signed certs, hostname mismatch
8. **HTTP security header audit** — CSP, HSTS, X-Frame-Options, CORS misconfiguration, insecure cookies, server version disclosure
9. **Technology stack fingerprinting** — detects CMS (WordPress, Drupal, Joomla), frameworks, cloud provider (AWS/Azure/GCP), CDN, and WAF
10. **DNS/email security assessment** — SPF, DKIM, DMARC, DNSSEC, zone transfer attempts, CAA records, email spoofability score
11. **Subdomain takeover detection** — discovers subdomains via CT logs then checks 25 cloud providers for dangling DNS
12. **Passive OSINT** without touching the target: Certificate Transparency logs, DNS enumeration (DoH), ASN/CIDR lookup
13. **Composite risk scoring** weighted by CVSS + CISA KEV exploit status + Metasploit/PoC availability + detection confidence
14. **Exports** machine-readable JSON (SIEM-ready), styled HTML reports, and rich terminal output

---

## Installation

```bash
git clone https://github.com/dmitryflynn/netlogic.git
cd netlogic
# No third-party Python dependencies — pure stdlib
python netlogic.py --version
```

---

## Usage

```bash
# Quick scan — 43 ports, CVE correlation
python netlogic.py scanme.nmap.org

# Deep TLS + header audit
python netlogic.py example.com --tls --headers

# Active probing: unauthenticated services, default creds, CVE confirmation
python netlogic.py 10.0.0.5 --probe

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

# Extended port range (58 ports)
python netlogic.py 10.0.0.5 --ports full

# Custom port list
python netlogic.py 10.0.0.5 --ports custom=22,80,443,8080,9200 --timeout 3

# Only show HIGH+ CVEs
python netlogic.py example.com --min-cvss 7.0

# Use NVD API key for faster lookups (recommended for --full scans)
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
| `--ports quick\|full\|custom=...` | Port set: quick (43 ports), full (58 ports), or comma-separated list |
| `--tls` | Deep SSL/TLS protocol, cipher, and certificate analysis |
| `--headers` | HTTP security header audit + CORS/cookie analysis |
| `--stack` | Technology stack + WAF fingerprinting |
| `--dns` | DNS/email security (SPF, DKIM, DMARC, DNSSEC, zone transfer) |
| `--takeover` | Subdomain takeover detection via CT logs + 25 provider fingerprints |
| `--osint` | Passive recon (DNS, CT logs, ASN) — no direct target contact |
| `--probe` | Active probing: unauthenticated service access, default credentials, CVE-specific confirms |
| `--full` | Run all of the above |
| `--report terminal\|json\|html\|all` | Output format |
| `--out <dir>` | Save reports to directory |
| `--cidr` | Treat target as CIDR block and sweep all hosts |
| `--min-cvss <score>` | Minimum CVSS score to report (default: 4.0) |
| `--nvd-key <key>` | NVD API key for 10× faster rate limits (or set `NETLOGIC_NVD_KEY` env var) |
| `--timeout <seconds>` | Per-port TCP timeout (default: 2.0) |
| `--threads <n>` | Max concurrent scan threads (default: 100) |
| `--cache-stats` | Show NVD disk cache info |
| `--clear-cache` | Clear NVD disk cache |
| `--preload-cache` | Pre-warm cache for common products |
| `--no-color` | Disable ANSI colors |
| `--json-stream` | Newline-delimited JSON events for Electron GUI |

---

## Example Output

```
══════════════════════════════════════════════════════════════════════
  NetLogic Scan Report
  Target : scanme.nmap.org
  IP     : 45.33.32.156
  OS Est.: Linux/Unix
  Runtime: 4.2s
══════════════════════════════════════════════════════════════════════

  OPEN PORTS
  PORT     SERVICE          PRODUCT/VERSION                     TLS
  22       ssh              OpenSSH 6.6.1p1 Ubuntu              –
  80       http             Apache/2.4.7                        –
  443      https                                                ✓ TLS
  6379     redis                                                –
  9200     elasticsearch                                        –

  VULNERABILITY FINDINGS
  Port 22/ssh (OpenSSH 6.6.1p1)
  [✓ version confirmed]
  Risk Score: 9.8/10

    🔴 CRITICAL  CVE-2023-38408  CVSS 9.8
    OpenSSH < 9.3p2 ssh-agent RCE via PKCS#11 provider loading.
    ⚡ Metasploit module available
    ⚡ Actively exploited (CISA KEV)

    🟠 HIGH      CVE-2018-15473  CVSS 5.3
    OpenSSH < 7.7 username enumeration via timing side-channel.

  SSL/TLS ANALYSIS
  Port 443 — Grade: C
  Protocols : TLSv1.3, TLSv1.2, TLSv1.1
  Deprecated: TLSv1.1
    MEDIUM  Deprecated Protocol Supported: TLSv1.1

  HTTP SECURITY HEADERS — Score: 45/100  Grade: F
  Missing: strict-transport-security, content-security-policy, x-frame-options
    HIGH  Missing HSTS Header
    HIGH  Missing Content-Security-Policy

  DNS & EMAIL SECURITY — Spoofability: 7/10 (SPOOFABLE)
  SPF    ✗  MISSING — anyone can spoof this domain
  DKIM   ✗  No selectors found
  DMARC  ✗  MISSING — no policy enforcement

  SERVICE MISCONFIGURATION FINDINGS  (3 issues, 18 probes run)

    🔴 CRITICAL  Redis — No Authentication Required
    Port 6379 / redis
    Redis 7.0.1 is fully accessible without a password. Attackers can read/write all
    data, load modules for RCE, or use SLAVEOF for lateral movement.
    Evidence   : INFO server returned redis_version:7.0.1
    Remediation: Set 'requirepass' in redis.conf; bind to 127.0.0.1; use Redis 6+ ACLs.

    🔴 CRITICAL  Elasticsearch — Open Access (No Authentication)
    Port 9200 / elasticsearch
    Elasticsearch cluster 'prod-cluster' v8.1.0 is open without authentication.
    Evidence   : GET / → HTTP 200; cluster_name='prod-cluster'; indices accessible=True

  ACTIVE VULNERABILITY PROBES  (1 confirmed, 12 probes run)

    🔴 CRITICAL  Apache 2.4.49 Path Traversal — /etc/passwd Retrieved  [CONFIRMED]
    CVE-2021-41773
    Path traversal confirmed. /etc/passwd is readable. If mod_cgi is enabled,
    this escalates to unauthenticated RCE (CVSS 9.8).
    Evidence   : GET /cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd → HTTP 200 with passwd
    Remediation: Upgrade Apache to 2.4.51+; disable mod_cgi; Require all denied.
```

---

## Architecture

```
netlogic/
├── netlogic.py               ← CLI entry point, flag routing, output orchestration
└── src/
    ├── scanner.py             ← TCP scanner, 22 service probes, banner grabbing (43 services)
    ├── cve_correlator.py      ← CVE correlation: NVD + 192 offline sigs, 89 banner patterns
    ├── nvd_lookup.py          ← NIST NVD API v2.0 client, disk cache, CISA KEV, 101 products
    ├── service_prober.py      ← Unauthenticated access, default creds, 33 admin panel paths
    ├── vuln_prober.py         ← CVE-specific safe active probes (path traversal, RCE confirm, etc.)
    ├── osint.py               ← DNS/DoH, CT logs (crt.sh), ASN lookup, HTTP fingerprinting
    ├── tls_analyzer.py        ← SSL/TLS deep analysis, POODLE/BEAST/CRIME/DROWN detection
    ├── header_audit.py        ← HTTP security header audit, CORS, cookie flags, scoring
    ├── stack_fingerprint.py   ← CMS, framework, cloud, CDN, WAF detection
    ├── dns_security.py        ← SPF, DKIM, DMARC, DNSSEC, zone transfer, spoofability score
    ├── takeover.py            ← Subdomain takeover detection (25 providers)
    ├── reporter.py            ← Terminal (ANSI), JSON, and HTML report generators
    └── json_bridge.py         ← Streaming JSON event emitter for Electron desktop app
```

### Scanner Engine (`scanner.py`)
- Concurrent TCP connect scanning via `ThreadPoolExecutor` (up to 100 threads)
- 43 mapped port/service combinations; 22 protocol-specific probes (HTTP GET, Redis INFO, MongoDB wire protocol, Docker API, etcd, Consul, Vault, Grafana, Kibana, Prometheus, RabbitMQ, Solr, Memcached, and more)
- Banner parsing with regex version extraction
- TLS handshake inspection + certificate CN extraction
- TTL-based OS fingerprinting (Linux / Windows / Network Device)

### CVE Correlator (`cve_correlator.py`) + NVD Lookup (`nvd_lookup.py`)
- **Live NIST NVD API v2.0** queries for every discovered product/version across 101 product keyword mappings
- **CISA KEV integration** — flags CVEs actively exploited in the wild
- **Exploit tracking** — 52 CVEs with confirmed Metasploit modules, 88 CVEs with public exploits/PoCs
- **Detection confidence** — HIGH (version from banner) / MEDIUM (product only) / LOW (port guess)
- **Disk cache** at `~/.netlogic/nvd_cache/` with 24-hour TTL
- **Offline fallback** — 192 hardcoded signatures across 89 banner patterns; used when NVD is unreachable
- Composite risk scoring: CVSS base + KEV bonus + Metasploit/PoC flag + detection confidence
- Optional API key (`--nvd-key` or `NETLOGIC_NVD_KEY`) for 10× faster queries

### Service Prober (`service_prober.py`) — activated by `--probe` or `--full`
Performs safe, read-only checks against every discovered open port:

| Service | Check |
|---|---|
| Redis | Unauthenticated access via INFO command |
| Memcached | Unauthenticated VERSION command |
| MongoDB | Wire protocol isMaster without credentials |
| Elasticsearch | Cluster info + index listing without auth |
| CouchDB | `/_all_dbs` without credentials |
| Docker API | `/version` on TCP port 2375 (host takeover vector) |
| Kubernetes API | Anonymous `/api` access |
| etcd | `/v2/keys` or `/v3/cluster` without auth (holds K8s secrets) |
| Consul | `/v1/catalog/services` without ACL tokens |
| Prometheus | `/metrics` and admin API without authentication |
| HashiCorp Vault | Uninitialized or unsealed state detection |
| RabbitMQ | Default `guest:guest` credentials on management API |
| InfluxDB | `SHOW DATABASES` without credentials |
| FTP | Anonymous login (USER anonymous) |
| HTTP (any port) | 33 admin panel paths: `.env`, `.git/config`, backup configs, Spring actuator (`/env`, `/heapdump`), Swagger, GraphQL, phpMyAdmin, Tomcat manager, JBoss consoles, Adminer, and more |

### Vulnerability Prober (`vuln_prober.py`) — activated by `--probe` or `--full`
CVE-specific safe active probes that attempt to confirm vulnerabilities:

| CVE | Title | What's Confirmed |
|---|---|---|
| CVE-2021-41773 | Apache 2.4.49 Path Traversal | Retrieves `/etc/passwd` via `/.%2e/` encoding |
| CVE-2021-42013 | Apache 2.4.50 Path Traversal | Double-encoded `%%32%65` variant |
| CVE-2021-43798 | Grafana Plugin Traversal | Retrieves `/etc/passwd` via plugin path |
| CVE-2014-6271 | Shellshock CGI RCE | Injects payload into User-Agent/Cookie, checks response |
| CVE-2020-1938 | Ghostcat AJP | CPING/CPONG handshake on port 8009 |
| CVE-2021-44228 | Log4Shell | JNDI header injection; Java error leakage indicates processing |
| CWE-215 | Spring Boot Actuator | `/env`, `/heapdump`, `/httptrace`, `/mappings`, `/loggers` |
| CWE-521 | Tomcat Default Creds | Tests 9 common credential pairs against `/manager/html` |
| CWE-601 | Open Redirect | 11 common redirect parameters tested |
| CWE-548 | Directory Listing | Detects Apache/Nginx index pages across common paths |
| CWE-200 | phpinfo() Exposure | `/phpinfo.php`, `/info.php`, and variants |
| CWE-200 | Backup/Config Files | `.env`, `.git/config`, `wp-config.php.bak`, `id_rsa`, `server.key`, and more — with credential keyword confirmation |
| CWE-22 | Nginx Alias Traversal | `/static../etc/passwd` off-by-one alias misconfiguration |
| CVE-2010-2730 | IIS Tilde Enumeration | 8.3 short filename disclosure detection |

### SSL/TLS Analyzer (`tls_analyzer.py`)
- Protocol version probing: TLSv1.0, TLSv1.1, TLSv1.2, TLSv1.3
- Cipher suite weakness detection: RC4, DES, 3DES, NULL, EXPORT, Anonymous DH
- Known vulnerability checks: POODLE (CVE-2014-3566), BEAST (CVE-2011-3389), CRIME (CVE-2012-4929), DROWN (CVE-2016-0800)
- Certificate analysis: expiry, self-signed, hostname mismatch, SAN coverage, wildcard scope
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

### DNS Security Checker (`dns_security.py`)
- **SPF**: presence, `all` mechanism strength, DNS lookup count (RFC 7208 limit of 10)
- **DKIM**: probes 25 common selectors, checks key length
- **DMARC**: policy enforcement level (`none`/`quarantine`/`reject`), subdomain policy, reporting addresses
- **DNSSEC**: DS and DNSKEY record verification
- **CAA**: certificate authority authorization records
- **Zone Transfer**: raw AXFR attempt against all nameservers
- **Wildcard DNS**: detects `*.domain` resolution
- **Email spoofability score**: 0–10 composite rating based on SPF + DKIM + DMARC posture

### Subdomain Takeover Detector (`takeover.py`)
- Discovers subdomains via Certificate Transparency logs (crt.sh)
- Follows full CNAME chains via Cloudflare DoH
- Fingerprint database for 25 providers: GitHub Pages, Heroku, Amazon S3, CloudFront, Netlify, Vercel, Azure, Shopify, Fastly, Ghost, Tumblr, WordPress.com, Zendesk, Surge.sh, Webflow, Squarespace, Wix, ReadTheDocs, Bitbucket, and more

### OSINT Module (`osint.py`)
- All queries use public APIs — zero direct contact with target
- `crt.sh` Certificate Transparency subdomain enumeration
- Cloudflare DoH for DNS records: A, AAAA, MX, TXT, NS, CNAME, SOA, SRV
- `ipinfo.io` for ASN/org/country lookup

### Reporter (`reporter.py`)
- **Terminal**: color-coded severity badges, confidence indicators, tiered exploit markers (Metasploit > public PoC > KEV), aligned tables
- **JSON**: structured schema compatible with Elastic SIEM / Splunk; embeds TLS, header, DNS, takeover, and probe results
- **HTML**: dark-themed report with stat cards and sortable tables

### Electron Desktop App (`json_bridge.py`)
- Streams scan results live to GUI via newline-delimited JSON events
- Events: `port`, `vuln`, `osint`, `tls`, `headers`, `dns`, `stack`, `service_probes`, `vuln_probes`, `progress`, `done`, `error`
- Distributable as Windows installer via PyInstaller + NSIS

---

## CVE Coverage

### Via Live NVD API (101 product mappings — always current)

| Service | Vulnerability Classes |
|---|---|
| OpenSSH | RCE via ssh-agent (KEV), priv-esc, username enumeration, scp injection |
| Apache HTTPD | Path traversal + RCE (Metasploit), request smuggling, mod_proxy SSRF |
| Nginx | HTTP/2 Rapid Reset DoS, DNS resolver heap overwrite, alias traversal |
| Microsoft IIS | Wormable HTTP stack RCE, WebDAV buffer overflow (Metasploit), tilde enumeration |
| PHP | FPM path_info RCE, password_verify overflow, unserialize injection |
| WordPress | PHP object injection RCE, SQL injection, REST API user enumeration |
| Drupal | Drupalgeddon2 unauthenticated RCE (Metasploit), REST API object injection |
| Joomla | Unauthenticated config read via REST API |
| Apache Tomcat | Ghostcat AJP file inclusion + RCE, default manager credentials |
| Spring Framework | Spring4Shell RCE via data binding, actuator credential exposure |
| Log4j | Log4Shell JNDI injection (CVE-2021-44228, CVSS 10.0) |
| Grafana | Plugin directory traversal (CVE-2021-43798), CSRF→RCE |
| Kibana | Timelion RCE (CVE-2019-7609) |
| Confluence | OGNL injection RCE (CVE-2022-26134, KEV) |
| Jira | Template injection, SSRF |
| Jenkins | Script console RCE, Git plugin arbitrary file read |
| Redis | Lua sandbox escape RCE, integer overflow, unauthenticated access |
| MongoDB | Unauthenticated access, cert validation bypass MITM |
| Elasticsearch | Data exposure, unauthenticated cluster access |
| CouchDB | Deserialization RCE (CVE-2022-24706), unauthenticated access |
| Memcached | UDP DRDoS amplification (51,000× factor), unauthenticated access |
| Vault | Auth bypass (CVE-2022-40186), uninitialized instance takeover |
| Consul | Unauthenticated API, Raft RCE (CVE-2021-37219) |
| etcd | Unauthenticated key-value access (Kubernetes secret exposure) |
| RabbitMQ | Default guest credentials, unauthenticated management API |
| InfluxDB | Auth bypass (CVE-2019-20933), unauthenticated queries |
| Prometheus | Unauthenticated metrics and target enumeration |
| Solr | DataImportHandler RCE (CVE-2019-0193) |
| MinIO | Environment variable key leak (CVE-2023-28432) |
| Docker daemon | Socket exposure, container escape (CVE-2019-5736) |
| Kubernetes API | Anonymous access, privilege escalation (CVE-2018-1002105) |
| vsftpd | Backdoor shell on 2.3.4 (Metasploit), anonymous login |
| ProFTPD | Unauthenticated file copy via mod_copy, anonymous login |
| Samba | Out-of-bounds heap write RCE via VFS fruit module |
| OpenSSL | Heartbleed memory disclosure, X.400 ASN.1 type confusion |
| Exim | Local privilege escalation, remote code execution |
| Splunk | XSLT RCE (CVE-2023-46214) |
| Exchange | ProxyLogon/ProxyShell chain (multiple KEV) |
| vCenter | RCE via JNDI/SSRF (CVE-2021-21985, KEV) |
| + any product | Live NVD API fallback — searches NIST for any product/version |

---

## Legal Notice

> **NetLogic is intended for authorized security assessments, penetration testing, and network administration only.**
> Scanning or probing hosts without explicit written permission is illegal in most jurisdictions.
> The author assumes no liability for unauthorized use.

---

## License

MIT © 2026 Dmitry Flynn — See [LICENSE](https://github.com/dmitryflynn/netlogic/blob/main/LICENSE)
