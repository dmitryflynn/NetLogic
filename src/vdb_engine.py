import sqlite3
import os
import json
import time
import threading
from dataclasses import dataclass
from typing import Optional, List

# Optimized for local lookup speed with dynamic SaaS paths
_data_dir = os.environ.get("NETLOGIC_DATA_DIR", os.path.join(os.path.expanduser("~"), ".netlogic"))
VDB_DIR = os.path.join(_data_dir, "vdb")
VDB_PATH = os.path.join(VDB_DIR, "vuln_db.sqlite")

PRODUCT_TEXT_HINTS = {
    "openssh": ("openssh", "openbsd ssh"),
    "apache": ("apache http server", "apache", "httpd"),
    "nginx": ("nginx",),
    "iis": ("microsoft iis", "iis", "http.sys"),
    "tomcat": ("tomcat", "apache tomcat", "ajp"),
    "php": ("php", "php-fpm", "php-cgi"),
    "mysql": ("mysql",),
    "mariadb": ("mariadb", "mysql"),
    "postgresql": ("postgresql", "postgres"),
    "redis": ("redis",),
    "mongodb": ("mongodb", "mongo db", "mongod"),
    "elasticsearch": ("elasticsearch",),
    "memcached": ("memcached",),
    "vsftpd": ("vsftpd",),
    "proftpd": ("proftpd",),
    "dovecot": ("dovecot",),
    "postfix": ("postfix",),
    "exim": ("exim",),
    "samba": ("samba",),
    "wordpress": ("wordpress", "wp-"),
    "drupal": ("drupal",),
    "jenkins": ("jenkins",),
    "grafana": ("grafana",),
    "kibana": ("kibana",),
    "docker": ("docker", "docker engine"),
    "kubernetes": ("kubernetes", "kube", "k8s"),
}

PRODUCT_NEGATIVE_HINTS = {
    "openssh": ("dropbear", "freesshd", "freeftpd", "tectia", "scponly", "akkadian", "vyos"),
}


def _vdb_description_matches_product(product: str, description: str) -> bool:
    """Defensive filter for legacy VDB rows imported from broad keyword searches."""
    product_l = str(product or "").lower()
    desc_l = str(description or "").lower()
    hints = PRODUCT_TEXT_HINTS.get(product_l)
    negative_hints = PRODUCT_NEGATIVE_HINTS.get(product_l, ())
    if any(hint in desc_l for hint in negative_hints):
        return False
    if not hints:
        return True
    return any(hint in desc_l for hint in hints)

@dataclass
class VdbResult:
    id: str
    description: str
    cvss: float
    severity: str
    version_range: str
    remediation: str
    version_start: Optional[str] = None
    version_end: Optional[str] = None
    version_end_inc: bool = False
    version_ranges: Optional[List[dict]] = None
    match_status: str = "POTENTIAL"
    kev: bool = False
    has_msf: bool = False

class VdbEngine:
    def __init__(self):
        self._local = threading.local()
        self._ensure_dir()

    def _ensure_dir(self):
        os.makedirs(VDB_DIR, exist_ok=True)

    def connect(self):
        # Reuse the per-thread connection; only run schema DDL once per fresh
        # connection. Re-running CREATE/ALTER on every call wasted work and —
        # worse — issued writes on what are otherwise read paths (is_initialized,
        # local_match, get_stats), which can fail on a read-only/corrupt file.
        if not getattr(self._local, "conn", None):
            self._local.conn = sqlite3.connect(VDB_PATH, check_same_thread=False, timeout=30.0)
            self._create_schema()
        return getattr(self._local, "conn")

    def _reset_connection(self):
        """Drop a (possibly broken) per-thread connection so the next connect()
        re-opens cleanly. Used after corruption errors so a transient bad handle
        is not cached for the life of the thread."""
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
            self._local.conn = None

    def _create_schema(self):
        conn = getattr(self._local, "conn")
        cursor = conn.cursor()
        # CPE Mapping (products)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY,
                keyword TEXT UNIQUE,
                cpe_vendor TEXT,
                cpe_product TEXT
            )
        ''')
        # CVE Data (indexed by product)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id TEXT PRIMARY KEY,
                product_id INTEGER,
                description TEXT,
                cvss REAL,
                severity TEXT,
                version_start TEXT,
                version_end TEXT,
                version_end_inc INTEGER,
                version_ranges_json TEXT,
                remediation TEXT,
                kev INTEGER DEFAULT 0,
                has_msf INTEGER DEFAULT 0,
                FOREIGN KEY(product_id) REFERENCES products(id)
            )
        ''')
        cols = [row[1] for row in cursor.execute("PRAGMA table_info(vulnerabilities)").fetchall()]
        if "version_ranges_json" not in cols:
            cursor.execute("ALTER TABLE vulnerabilities ADD COLUMN version_ranges_json TEXT")
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_vuln_product ON vulnerabilities(product_id)')
        # Metadata table for tracking VDB state
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT,
                updated_at INTEGER
            )
        ''')
        conn.commit()

    def is_initialized(self) -> bool:
        if not os.path.exists(VDB_PATH):
            return False
        try:
            conn = self.connect()
            res = conn.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()
            return res[0] > 0
        except Exception:
            # Corrupt/locked/partially-written DB. Fail soft (offline CVE
            # correlation simply degrades) and drop the bad handle so a later
            # call after a successful re-sync can recover instead of reusing it.
            self._reset_connection()
            return False

    def local_match(self, product: str, version: str) -> List[VdbResult]:
        """High-speed local CVE matching without API.

        Hard contract: this must NEVER raise — a failing offline lookup must
        only degrade correlation, never crash a scan. Any DB/parse error fails
        soft to an empty list.
        """
        try:
            return self._local_match(product, version)
        except Exception:
            # Corruption/lock mid-query: drop the bad handle and degrade quietly.
            self._reset_connection()
            return []

    def _local_match(self, product: str, version: str) -> List[VdbResult]:
        if not product or not version or not self.is_initialized():
            return []

        conn = self.connect()
        cursor = conn.cursor()

        # 1. Resolve product to ID
        res = cursor.execute(
            "SELECT id FROM products WHERE keyword = ?", (product.lower(),)
        ).fetchone()
        if not res:
            return []

        product_id = res[0]

        # 2. Fetch all CVEs for this product
        # We perform version filtering in Python for maximum flexibility
        cursor.execute(
            "SELECT id, description, cvss, severity, version_start, version_end, version_end_inc, "
            "version_ranges_json, remediation, kev, has_msf "
            "FROM vulnerabilities WHERE product_id = ?", (product_id,)
        )

        from src.nvd_lookup import _parse_ver, version_is_affected, NVDCve
        try:
            _parse_ver(version)
        except Exception:
            return []

        rows = cursor.fetchall()
        confirmed = []
        potential = []
        # Track whether any *relevant* (description-matching) row actually carried
        # version-range data. Used below to decide whether an empty CONFIRMED set
        # means "version filtered out" (suppress) vs. "no range data at all".
        relevant_range_data_seen = False

        for row in rows:
            cve_id, desc, cvss, sev, v_start, v_end, v_inc, ranges_json, rem, kev, msf = row
            try:
                version_ranges = json.loads(ranges_json) if ranges_json else []
            except Exception:
                version_ranges = []
            # Defensive: a stored "[]" decodes to an empty list (no ranges), and
            # a non-list payload (corrupt row) must not be treated as range data.
            if not isinstance(version_ranges, list):
                version_ranges = []

            if not _vdb_description_matches_product(product, desc):
                continue

            if v_start or v_end or version_ranges:
                relevant_range_data_seen = True

            if not v_start and not v_end and not version_ranges:
                # No range — POTENTIAL match (product keyword hit, version unverified)
                # Only include if CVSS >= 7.0 to limit noise
                if cvss >= 7.0:
                    potential.append(VdbResult(
                        id=cve_id, description=desc, cvss=cvss, severity=sev,
                        version_range="[POTENTIAL — version range not in database]",
                        remediation=rem, version_ranges=[],
                        match_status="POTENTIAL", kev=bool(kev), has_msf=bool(msf)
                    ))
                continue

            # Version filtering logic — CONFIRMED path
            cve = NVDCve(
                id=cve_id,
                description=desc,
                cvss_score=cvss,
                severity=sev,
                vector="",
                published="",
                last_modified="",
                cwe="",
                version_start=v_start,
                version_end=v_end,
                version_end_including=bool(v_inc),
                version_ranges=version_ranges or [],
            )
            is_affected = True
            try:
                is_affected = version_is_affected(version, cve, detected_product=product)
            except Exception:
                continue  # Skip malformed ranges

            if is_affected:
                if version_ranges:
                    range_summary = []
                    for r in version_ranges[:3]:
                        seg = []
                        if r.get("start"):
                            seg.append(f">= {r['start']}")
                        if r.get("end"):
                            op = "<= " if r.get("end_including") else "< "
                            seg.append(op + r["end"])
                        if seg:
                            range_summary.append(", ".join(seg))
                    version_range = " | ".join(range_summary) if range_summary else "[CONFIRMED]"
                else:
                    version_range = f"{v_start or '*'} to {'incl.' if v_inc else ''}{v_end or '*'}"
                confirmed.append(VdbResult(
                    id=cve_id, description=desc, cvss=cvss, severity=sev,
                    version_range=version_range,
                    version_start=v_start, version_end=v_end,
                    version_end_inc=bool(v_inc), version_ranges=version_ranges or [],
                    remediation=rem, match_status="CONFIRMED",
                    kev=bool(kev), has_msf=bool(msf)
                ))

        # Merge: all confirmed + capped potential.
        # If a relevant row carried version-range data yet nothing CONFIRMED,
        # trust the version filter and return no CVEs — emitting the version-less
        # POTENTIAL rows here would risk a false positive on a patched target.
        # NOTE: we use the parsed-per-row flag, not the raw row columns: an
        # imported row stores "[]" (an empty JSON array string) for "no ranges",
        # which is truthy as a string and previously suppressed legitimate
        # POTENTIAL matches.
        if not confirmed and relevant_range_data_seen:
            return []

        # Potential cap: 5 if <5 confirmed, else 2 (noise reduction)
        confirmed.sort(key=lambda x: x.cvss, reverse=True)
        potential.sort(key=lambda x: x.cvss, reverse=True)
        pot_cap = 5 if len(confirmed) < 5 else 2
        return confirmed + potential[:pot_cap]

    def import_nvd_data(self, product_kw: str, cves: list):
        """Mass-import NVD data into local SQLite."""
        if not cves:
            return

        try:
            conn = self.connect()
            cursor = conn.cursor()
            
            # Ensure product exists
            cursor.execute(
                "INSERT OR IGNORE INTO products (keyword) VALUES (?)",
                (product_kw.lower(),)
            )
            res = cursor.execute(
                "SELECT id FROM products WHERE keyword = ?", (product_kw.lower(),)
            ).fetchone()
            if res is None:
                return
            product_id = res[0]
            
            # Bulk Insert CVEs
            for cve in cves:
                cursor.execute('''
                    INSERT OR REPLACE INTO vulnerabilities (
                        id, product_id, description, cvss, severity, 
                        version_start, version_end, version_end_inc, version_ranges_json,
                        remediation, kev, has_msf
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    cve.id, product_id, cve.description, cve.cvss_score, cve.severity,
                    cve.version_start, cve.version_end, 1 if cve.version_end_including else 0,
                    json.dumps(getattr(cve, "version_ranges", []) or []),
                    f"Apply vendor security patches. Refer to: {cve.references[0] if cve.references else 'NVD'}",
                    1 if cve.kev else 0, 1 if cve.has_metasploit else 0
                ))
            
            conn.commit()
        except Exception:
            self._reset_connection()
            raise

    def record_sync(self, product_count: int = 0, cve_count: int = 0):
        """Record a VDB sync event with timestamp."""
        conn = self.connect()
        cursor = conn.cursor()
        now = int(time.time())
        cursor.execute(
            "INSERT OR REPLACE INTO metadata (key, value, updated_at) VALUES (?, ?, ?)",
            ("last_sync", f"{product_count}:{cve_count}", now)
        )
        conn.commit()

    def get_last_sync_time(self) -> Optional[int]:
        """Returns Unix timestamp of last sync, or None if never synced."""
        try:
            conn = self.connect()
            res = conn.execute(
                "SELECT updated_at FROM metadata WHERE key = 'last_sync'"
            ).fetchone()
            return res[0] if res else None
        except Exception:
            return None

    def get_freshness_status(self) -> dict:
        """Returns VDB freshness info."""
        last_sync = self.get_last_sync_time()
        if not last_sync:
            return {"status": "never_synced", "days_old": None, "message": "VDB has never been synced"}

        # Clamp to >= 0: a clock that moved backwards since the last sync (DST,
        # NTP correction, VM snapshot) would otherwise yield a negative age and
        # mislabel an arbitrarily old DB as freshly synced.
        age_seconds = max(0.0, time.time() - last_sync)
        days_old = age_seconds / 86400

        if days_old > 30:
            status = "stale"
            msg = f"VDB is {int(days_old)} days old — consider re-syncing for latest CVEs"
        elif days_old > 7:
            status = "aging"
            msg = f"VDB is {int(days_old)} days old — some CVEs may be missing"
        else:
            status = "fresh"
            msg = f"VDB synced {int(days_old)} days ago"

        return {"status": status, "days_old": int(days_old), "message": msg}

    def get_stats(self) -> dict:
        """Returns VDB statistics."""
        try:
            conn = self.connect()
            vuln_count = conn.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]
            product_count = conn.execute("SELECT COUNT(*) FROM products").fetchone()[0]
            kev_count = conn.execute("SELECT COUNT(*) FROM vulnerabilities WHERE kev = 1").fetchone()[0]
            msf_count = conn.execute("SELECT COUNT(*) FROM vulnerabilities WHERE has_msf = 1").fetchone()[0]
            return {
                "vulnerabilities": vuln_count,
                "products": product_count,
                "kev_count": kev_count,
                "msf_count": msf_count,
                "freshness": self.get_freshness_status()
            }
        except Exception as e:
            return {"error": str(e)}

vdb_engine = VdbEngine()
