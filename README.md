# NetRecon 🔍

**Attack Surface Mapper & Vulnerability Correlator**

NetRecon is a professional-grade network security reconnaissance tool that combines active port scanning, passive OSINT, and automated CVE correlation into a single workflow — replacing what typically requires three or four separate tools and manual cross-referencing.

![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue)
![License: MIT](https://img.shields.io/badge/License-MIT-green)
![Platform: Linux/macOS](https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey)

---

## What makes this different?

Most scanners stop at port discovery. NetRecon continues:

1. **Fingerprints** running services and extracts version strings via custom protocol probes (SSH, HTTP, FTP, Redis, MySQL, MongoDB…)
2. **Correlates** discovered versions against a local CVE signature database *and* the live NIST NVD API
3. **Flags misconfigurations** — unauthenticated Redis, exposed Docker socket, default MongoDB, etc.
4. **Runs passive OSINT** without touching the target: Certificate Transparency logs, DNS enumeration (DoH), ASN/CIDR lookup, HTTP technology fingerprinting
5. **Calculates composite risk scores** weighted by CVSS + exploit availability
6. **Exports** machine-readable JSON (SIEM-ready), styled HTML reports, and rich terminal output

---

## Installation

```bash
git clone https://github.com/yourusername/netrecon.git
cd netrecon
# No dependencies beyond Python 3.9+ standard library
python netrecon.py --version
```

---

## Usage

```bash
# Quick scan with terminal report
python netrecon.py scanme.nmap.org

# Full port scan + passive recon + HTML report
python netrecon.py example.com --ports full --osint --report html --out ./reports

# CIDR block sweep (internal network audit)
python netrecon.py 192.168.1.0/24 --cidr --report json --out ./reports

# Custom port list, verbose timeout
python netrecon.py 10.0.0.5 --ports custom=22,80,443,8080,9200 --timeout 3
```

---

## Example Output

```
═══════════════════════════════════════════════════════════════════════
  NetRecon Scan Report
  Target : scanme.nmap.org
  IP     : 45.33.32.156
  OS Est.: Linux/Unix
  Runtime: 4.2s
═══════════════════════════════════════════════════════════════════════

  OPEN PORTS
  PORT     SERVICE          PRODUCT/VERSION                     TLS
  22       ssh              OpenSSH 6.6.1p1 Ubuntu              –
  80       http             Apache/2.4.7                        –
  443      https                                                ✓ TLS

  VULNERABILITY FINDINGS

  Port 22/ssh (OpenSSH 6.6.1p1)
  Risk Score: 8.5/10

    🔴 CRITICAL  CVE-2021-41617  CVSS 7.0
    OpenSSH < 8.5 privilege escalation via PKCS#11 providers.
    ⚡ Known exploit available

    🟠 HIGH      CVE-2018-15473  CVSS 5.3
    OpenSSH < 7.7 username enumeration via response timing.

  Port 80/http (Apache 2.4.7)
  Risk Score: 9.8/10

    🔴 CRITICAL  CVE-2021-41773  CVSS 9.8
    Apache 2.4.49 path traversal and RCE — actively exploited.
    ⚡ Known exploit available
```

---

## Architecture

```
netrecon/
├── netrecon.py          ← CLI entry point
└── src/
    ├── scanner.py        ← TCP port scanner, service prober, banner grabber
    ├── cve_correlator.py ← CVE signature DB + NIST NVD live API correlation
    ├── osint.py          ← DNS/DoH, CT logs (crt.sh), ASN lookup, HTTP fingerprint
    └── reporter.py       ← Terminal (ANSI), JSON, and HTML report generators
```

### Scanner Engine (`scanner.py`)
- Concurrent TCP connect scanning via `ThreadPoolExecutor`
- Per-service protocol probes (HTTP GET, Redis INFO, MongoDB wire protocol…)
- Banner parsing with regex version extraction
- TLS handshake inspection + certificate CN extraction
- TTL-based OS fingerprinting

### CVE Correlator (`cve_correlator.py`)
- Offline signature database for the most exploited services (OpenSSH, Apache, nginx, MySQL, Redis, vsftpd, MongoDB, Elasticsearch, Docker, Kubernetes, RDP, SMB…)
- Semantic version range comparisons (handles `1.2.3-p4` style strings)
- Live NIST NVD API v2.0 fallback for unlisted products
- Exploit-availability bonus in risk scoring

### OSINT Module (`osint.py`)
- All queries use public APIs — zero direct contact with target
- `crt.sh` Certificate Transparency log enumeration
- Cloudflare DoH for DNS record collection (A, MX, TXT, NS, CNAME, SOA, SRV)
- `ipinfo.io` for ASN/org/country lookup
- HTTP header technology stack fingerprinting

### Reporter (`reporter.py`)
- **Terminal**: color-coded severity badges, aligned tables
- **JSON**: structured schema compatible with Elastic SIEM / Splunk
- **HTML**: dark-themed professional report with stat cards

---

## Flags & Detection Covered

| Service | Vulnerability Class |
|---|---|
| OpenSSH | Priv-esc, user enumeration, auth bypass |
| Apache httpd | Path traversal, request smuggling, RCE |
| nginx | Memory corruption |
| MySQL / MariaDB | DoS, use-after-free |
| Redis | Unauthenticated access, Lua RCE, integer overflow |
| vsftpd | Backdoor shell (2.3.4) |
| ProFTPD | OOB read, RCE |
| Elasticsearch | Data exposure, unauth API |
| MongoDB | Unauthenticated access |
| Memcached | DRDoS amplification surface |
| Docker daemon | Socket exposure, container escape |
| Kubernetes API | Privilege escalation |
| SMB | EternalBlue / WannaCry |
| RDP | BlueKeep pre-auth RCE |
| VNC | Credential interception |
| Telnet/FTP | Plaintext credential transmission |

---

## Legal Notice

> **NetRecon is intended for authorized security assessments, penetration testing, and network administration only.**
> Scanning hosts without explicit written permission is illegal in most jurisdictions.
> The author assumes no liability for unauthorized use.

---

## License

MIT © 2024 — See [LICENSE](LICENSE)
