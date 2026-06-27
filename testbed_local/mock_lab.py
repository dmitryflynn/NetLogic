#!/usr/bin/env python3
"""
NetLogic Mock Service Lab  —  Docker-free precision/recall measurement.
=======================================================================
Spins up tiny in-process TCP servers on 127.0.0.1 that emit real, version-pinned
service banners, then runs NetLogic's actual scan + correlation pipeline against
them and scores the results against an independently-defined ground truth.

This measures the thing NetLogic's headline feature depends on: how accurately it
turns a service banner into the correct set of CVEs. It does NOT measure live
exploitation — only detection + correlation, which is exactly what the engine
claims to do.

The set is deliberately adversarial: boundary versions (just past a patch line),
a distro backport, a patched-modern build, a product-name substring trap
(phpMyAdmin must not inherit PHP's CVEs), an unsupported product, and a
version-less banner. Those last two are honest RECALL gaps — things a banner-only
scanner cannot catch — so the recall number reflects real-world coverage limits.

Runs offline (NVD disabled) so results are deterministic and reproducible on any
machine. Cost is a handful of threads — no containers, no VMs.

    python testbed_local/mock_lab.py
"""
from __future__ import annotations

import socket
import sys
import threading
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import src.nvd_lookup as nvd
nvd._nvd_unavailable = True  # force deterministic offline correlation

from src.scanner import scan_host                      # noqa: E402
from src.cve_correlator import correlate               # noqa: E402

HTTP = "HTTP"

# Each mock: port, banner (bytes, or HTTP), label, and:
#   truth      — CVEs that SHOULD be reported for this exact version (independent
#                ground truth; conservative — only CVEs confidently applicable).
#   must_not   — CVEs that would be flatly WRONG to report (counted as FPs).
#   potential  — True if this finding should be labelled POTENTIAL (unverifiable).
#   gap        — True if this is an intentional recall gap (tool can't catch it).
MOCKS = [
    dict(port=12121, banner=b"220 (vsFTPd 2.3.4)\r\n", label="vsftpd 2.3.4",
         truth={"CVE-2011-2523"}, must_not=set(), potential=False),

    dict(port=12221, banner=b"SSH-2.0-OpenSSH_7.6p1\r\n", label="OpenSSH 7.6 (clean)",
         truth={"CVE-2021-41617", "CVE-2018-15473", "CVE-2023-38408"},
         must_not=set(), potential=False),

    # Boundary: 8.5 is NOT < 8.5, so CVE-2021-41617 / CVE-2018-15473 must NOT fire.
    dict(port=12222, banner=b"SSH-2.0-OpenSSH_8.5p1\r\n", label="OpenSSH 8.5 (boundary)",
         truth={"CVE-2023-38408"},
         must_not={"CVE-2021-41617", "CVE-2018-15473"}, potential=False),

    # Patched-modern: no legacy signature may fire.
    dict(port=12223, banner=b"SSH-2.0-OpenSSH_9.9p1\r\n", label="OpenSSH 9.9 (patched)",
         truth=set(),
         must_not={"CVE-2023-38408", "CVE-2021-41617", "CVE-2018-15473", "CVE-2016-3115"},
         potential=False),

    # Distro backport: same CVEs apply but must be flagged POTENTIAL, not confirmed.
    dict(port=12224, banner=b"SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.7\r\n",
         label="OpenSSH 7.6 (Ubuntu backport)",
         truth={"CVE-2021-41617", "CVE-2018-15473", "CVE-2023-38408"},
         must_not=set(), potential=True),

    dict(port=18080, banner=HTTP, label="Apache 2.4.49", http_server="Apache/2.4.49 (Unix)",
         truth={"CVE-2021-41773"}, must_not=set(), potential=False),

    # Substring trap: phpMyAdmin must NOT inherit PHP's CVEs (the 'php' in
    # 'phpmyadmin' bug). truth = a real phpMyAdmin CVE; must_not = PHP RCEs.
    dict(port=18081, banner=HTTP, label="phpMyAdmin 4.8.0",
         http_body='<meta name="application-name" content="phpMyAdmin 4.8.0">',
         truth={"CVE-2018-19968"},
         must_not={"CVE-2024-4577", "CVE-2019-11043", "CVE-2022-31626", "CVE-2012-1823"},
         potential=False),

    # RECALL GAP: unsupported product (Dropbear, not OpenSSH) — tool can't fingerprint it.
    dict(port=12225, banner=b"SSH-2.0-dropbear_2016.72\r\n", label="Dropbear 2016.72 (unsupported)",
         truth={"CVE-2016-7406"}, must_not=set(), potential=False, gap=True),

    # RECALL GAP: version-less banner — the hard ceiling of banner-only scanning.
    dict(port=18082, banner=HTTP, label="nginx (no version)", http_server="nginx",
         truth={"CVE-2021-23017"}, must_not=set(), potential=False, gap=True),
]


def _serve(mock: dict, stop: threading.Event):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(("127.0.0.1", mock["port"]))
    except OSError as e:
        mock["bind_error"] = str(e)
        return
    srv.listen(8)
    srv.settimeout(0.5)
    mock["bound"] = True
    while not stop.is_set():
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        try:
            if mock["banner"] == HTTP:
                try:
                    conn.settimeout(1.0)
                    conn.recv(2048)
                except OSError:
                    pass
                body = mock.get("http_body", "")
                headers = ["HTTP/1.1 200 OK"]
                if mock.get("http_server"):
                    headers.append(f"Server: {mock['http_server']}")
                headers.append("Content-Type: text/html")
                headers.append(f"Content-Length: {len(body)}")
                headers.append("Connection: close")
                resp = ("\r\n".join(headers) + "\r\n\r\n" + body).encode()
                conn.sendall(resp)
            else:
                conn.sendall(mock["banner"])
                time.sleep(0.1)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass
    srv.close()


def run():
    stop = threading.Event()
    for m in MOCKS:
        threading.Thread(target=_serve, args=(m, stop), daemon=True).start()
    time.sleep(0.6)

    live = [m for m in MOCKS if m.get("bound")]
    ports = [m["port"] for m in live]
    print(f"\n  Mock lab: {len(live)}/{len(MOCKS)} services up on 127.0.0.1 — "
          f"offline/deterministic mode\n")

    host = scan_host("127.0.0.1", ports=ports, timeout=3.0)
    matches = correlate(host.ports, min_cvss=0.0, verbose=False)
    by_port = {m.port: m for m in matches}

    tp = fp = fn = 0
    fp_detail, label_ok = [], 0
    print(f"  {'service':32}{'found':>7}{'missed':>8}{'false+':>8}  {'label'}")
    print("  " + "-" * 70)
    for m in live:
        vm = by_port.get(m["port"])
        reported = {c.id for c in vm.cves} if vm else set()
        truth, must_not = m["truth"], m["must_not"]

        hits = reported & truth
        miss = truth - reported
        bad = reported & must_not          # provably-wrong findings = false positives
        tp += len(hits); fn += len(miss); fp += len(bad)
        for b in bad:
            fp_detail.append(f"{m['label']}: {b}")

        conf = vm.detection_confidence if vm else "—"
        lab = (conf == "POTENTIAL") == bool(m.get("potential"))
        label_ok += int(lab)

        tag = "gap" if m.get("gap") else ("⚠" if bad or (miss and not m.get("gap")) else "ok")
        print(f"  {m['label']:32}{len(hits):>3}/{len(truth):<3}{len(miss):>8}{len(bad):>8}  "
              f"{conf:<10} {'✓' if lab else '✗'}  {tag}")

    stop.set()
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    gaps = sum(1 for m in live if m.get("gap"))

    print("  " + "-" * 70)
    print(f"\n  Precision: {precision*100:.0f}%   (false positives: {fp})")
    print(f"  Recall:    {recall*100:.0f}%   ({fn} missed of {tp+fn} ground-truth CVEs; "
          f"{gaps} are known coverage gaps)")
    print(f"  F1:        {f1*100:.0f}%      Confidence-label accuracy: {label_ok}/{len(live)}")
    if fp_detail:
        print(f"  False positives: {', '.join(fp_detail)}")
    print("\n  Scope: banner→version→CVE detection on controlled services (offline")
    print("  signature engine). Recall gaps = unsupported product + version-less banner.\n")


if __name__ == "__main__":
    run()
