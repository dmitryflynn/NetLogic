#!/usr/bin/env python3
"""
NetLogic Offline VDB Syncer
===========================
Downloads the latest CVE data from the NVD API into the local SQLite database
(~/.netlogic/vdb/vuln_db.sqlite) so scans can correlate vulnerabilities fully
offline. This is the mechanism that keeps a user's local CVE database current.

Run it:
    python -m src.vdb_syncer             # sync all focus products
    python -m src.vdb_syncer --limit 10  # quick partial sync (first 10 products)
    python -m src.vdb_syncer --status    # show freshness/stats only
"""
import os
import sys
from pathlib import Path

# Allow running as a standalone script (`python src/vdb_syncer.py`) as well as a
# module (`python -m src.vdb_syncer`) — bootstrap the project root onto sys.path
# before the package-qualified imports below.
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from src.vdb_engine import vdb_engine
from src.nvd_lookup import query_nvd_for_product, PRODUCT_KEYWORD_MAP

# ─── Top Enterprise Product List (Seed) ──────────────────────────────────────
# Syncing these first provides ~80% coverage for typical enterprise networks.
# Deduplicate by NVD keyword (not by internal key) and skip generic/None entries.
# e.g. "openssh" and "ssh" both map to "OpenSSH" — only sync once.
_seen_keywords: set = set()
SYNC_TARGETS: list = []
for _k, _v in PRODUCT_KEYWORD_MAP.items():
    if _v is not None and _v not in _seen_keywords:
        _seen_keywords.add(_v)
        SYNC_TARGETS.append(_k)

def run_vdb_sync(limit: int = 0, is_gui: bool = False):
    """
    Builds the local offline VDB by mass-querying and caching the NVD database.
    This enables 100% offline vulnerability auditing.
    """
    def log(text, level="info"):
        if is_gui:
            from src.json_bridge import emit
            emit("log", {"text": text, "level": level})
        else:
            print(f"  {text}")

    targets = SYNC_TARGETS
    if limit > 0:
        targets = SYNC_TARGETS[:limit]

    log(f"Starting Offline VDB Sync ({len(targets)} focus products)")
    if not os.environ.get("NETLOGIC_NVD_KEY"):
        log("No NVD API key (NETLOGIC_NVD_KEY) set — NVD limits you to ~5 requests "
            "per 30s, so a full sync is slow and may hit rate limits. Get a free key "
            "at https://nvd.nist.gov/developers/request-an-api-key", "warn")
    if is_gui:
        from src.json_bridge import emit
        emit("progress", {"percent": 5, "status": "Initializing VDB..."})

    success_count = 0
    total_cves = 0

    for i, product in enumerate(targets):
        try:
            # Update progress
            pct = 5 + int((i / len(targets)) * 90)
            if is_gui:
                from src.json_bridge import emit
                emit("progress", {"percent": pct, "status": f"Syncing {product}..."})
            
            # 1. Fetch from NVD — query_nvd_for_product paginates internally
            cves = query_nvd_for_product(product, max_results=2000)
            
            # 2. Persist to SQLite VDB
            if cves:
                vdb_engine.import_nvd_data(product, cves)
                success_count += 1
                total_cves += len(cves)
                log(f"Synced {product}: {len(cves)} CVEs cached.")
            else:
                log(f"Skipped {product}: No records found.", "warn")
        except Exception as e:
            log(f"Error syncing {product}: {e}", "error")

    # Only update the freshness clock if we actually imported something. A sync
    # that fetched nothing (NVD unreachable / rate-limited) must NOT mark the
    # database "fresh" — that would hide the failure behind a green timestamp.
    if success_count > 0:
        vdb_engine.record_sync(success_count, total_cves)
        log(f"VDB Sync Complete! {success_count} products, {total_cves} CVEs locally stored.", "success")
    else:
        log("VDB Sync fetched 0 records — NVD may be unreachable or rate-limited. "
            "Existing database left unchanged (freshness not updated).", "error")
    if is_gui:
        from src.json_bridge import emit
        emit("progress", {"percent": 100, "status": "VDB Sync Complete."})
        emit("done", {"ports": 0, "vulns": total_cves, "duration": 0})

    return {"products": success_count, "cves": total_cves}


def print_status() -> None:
    """Print the local offline VDB freshness and counts."""
    stats = vdb_engine.get_stats()
    if "error" in stats:
        print(f"  Offline VDB error: {stats['error']}")
        return
    fresh = stats.get("freshness", {})
    print("  NetLogic Offline VDB")
    print(f"    Vulnerabilities : {stats.get('vulnerabilities', 0):,}")
    print(f"    Products        : {stats.get('products', 0)}")
    print(f"    CISA KEV        : {stats.get('kev_count', 0)}")
    print(f"    Metasploit      : {stats.get('msf_count', 0)}")
    print(f"    Freshness       : {fresh.get('message', 'unknown')}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        prog="vdb_syncer",
        description="Sync the local offline CVE database from NVD so scans can "
                    "correlate vulnerabilities without live API calls.",
    )
    parser.add_argument("--limit", type=int, default=0,
                        help="Sync only the first N focus products (0 = all).")
    parser.add_argument("--status", action="store_true",
                        help="Show current VDB freshness/stats and exit.")
    args = parser.parse_args()

    if args.status:
        print_status()
        sys.exit(0)

    run_vdb_sync(limit=args.limit)
    print()
    print_status()
