"""Multi-host orchestration for cross-host attack chain discovery.

Runs the full run_scan() pipeline per host, aggregates fusion results,
builds cross-host context from shared services/tech across hosts, and
enables unified cross-host analysis in the synthesis narrative.
"""

from __future__ import annotations

from typing import Callable, Optional

from src.fusion.cross_host import cross_host_context


def run_multi_scan(targets: list[str], ports: list, args,
                   emit: Optional[Callable] = None,
                   scan_fn: Optional[Callable] = None) -> dict:
    """Run full scans across multiple hosts and return aggregated results.

    Each host gets the complete run_scan() pipeline. Results are aggregated
    with cross-host correlation so the synthesis can narrate multi-hop chains.

    Args:
        targets: hostnames/IPs to scan
        ports: port list
        args: scan options (SimpleNamespace or argparse.Namespace)
        emit: streaming event callback
        scan_fn: optional per-host scan function; defaults to engine.run_scan.
                 Pass src.deep.run_deep_scan for deep-probe mode.

    Returns:
        hosts: list of per-host artifacts dicts from run_scan()
        cross_host_context: structured cross-host groupings (or None)
        host_count: number of hosts scanned
        errors: list of (target, error) tuples for failed scans
    """
    if scan_fn is None:
        from src.engine import run_scan as scan_fn  # noqa: PLC0415

    host_arts: list[dict] = []
    errors: list[tuple[str, str]] = []
    total = len(targets)

    for i, target in enumerate(targets):
        msg = f"Scanning {target} ({i+1}/{total})"
        if emit:
            emit("progress", {"percent": int((i / total) * 100),
                              "status": f"Host {i+1}/{total}: {target}"},
                 message=msg)
        else:
            print(f"\n{'='*60}")
            print(f"  HOST {i+1}/{total}: {target}")
            print(f"{'='*60}\n")

        try:
            art = scan_fn(target, ports, args, emit=emit)
            host_arts.append(art)
        except Exception as exc:
            errors.append((target, str(exc)))
            if emit:
                emit("log", {"text": f"Host {target}: scan failed ({exc})",
                             "level": "error"})
            else:
                print(f"[!] Host {target}: scan failed — {exc}")

    # Build cross-host context from aggregated fusion verdicts
    host_verdicts: dict[str, list[dict]] = {}
    for art in host_arts:
        hr = art.get("host_result")
        host_ip = getattr(hr, "ip", None) if hr else None
        if not host_ip:
            idx = host_arts.index(art)
            host_ip = targets[idx] if idx < len(targets) else "unknown"
        fusion = art.get("fusion", {})
        verdicts = fusion.get("detected_vulnerabilities", [])
        if verdicts:
            host_verdicts[host_ip] = verdicts

    chx = cross_host_context(host_verdicts) if len(host_verdicts) >= 2 else None

    if chx and not emit:
        _print_cross_host_summary(chx)

    return {
        "hosts": host_arts,
        "cross_host_context": chx,
        "host_count": total,
        "errors": errors,
    }


def _print_cross_host_summary(chx: dict) -> None:
    """Print cross-host groupings to the terminal."""
    groups = chx.get("multi_host_groups", [])
    if not groups:
        return
    print(f"\n{'='*60}")
    print("  CROSS-HOST ANALYSIS")
    print(f"{'='*60}\n")
    for g in groups:
        print(f"  {g['label']}")
        print(f"  Hosts: {', '.join(g['hosts'])}")
        print(f"  Correlation: {g['correlation_type']}")
    print()
