#!/usr/bin/env python3
"""
NetLogic Remote Agent

Connects to a NetLogic controller, polls for scan jobs, and executes them
using the local scan engine.  Results are streamed back to the controller
in real-time so dashboard SSE consumers see live progress.

Quick start
───────────
1. Create an API key on the controller (admin only, one-time):

       curl -X POST http://localhost:8000/auth/keys \\
            -H "X-Admin-Key: $NETLOGIC_ADMIN_KEY" \\
            -H "Content-Type: application/json" \\
            -d '{"org_id": "acme"}'

2. Register and start this agent (first run):

       python netlogic_agent.py \\
           --controller http://localhost:8000 \\
           --api-key <key-from-step-1>

3. Subsequent runs (credentials saved to ~/.netlogic/agent.json):

       python netlogic_agent.py --controller http://localhost:8000

Environment variables
─────────────────────
  NETLOGIC_CONTROLLER   Controller base URL (overrides --controller)
  NETLOGIC_API_KEY      API key for first-time registration (overrides --api-key)
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

# ── Bootstrap project root so scan engine imports work ───────────────────────
_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

# ── Agent constants ───────────────────────────────────────────────────────────
AGENT_VERSION       = "1.0.0"
CAPABILITIES        = ["scan", "tls", "dns", "headers", "osint", "probe", "takeover", "stack"]
HEARTBEAT_INTERVAL  = 25    # seconds between heartbeats (server marks offline at 60 s)
POLL_INTERVAL_IDLE  = 5     # seconds between task polls when idle
EVENT_BATCH_SIZE    = 50    # flush events after this many accumulate
EVENT_FLUSH_SECS    = 2     # also flush every N seconds regardless of batch size

log = logging.getLogger("netlogic-agent")


# ── Minimal stdlib HTTP client ────────────────────────────────────────────────

def _http(method: str, url: str, body=None, token: str | None = None) -> dict:
    """Single-function HTTP client — no third-party deps required."""
    data = json.dumps(body).encode() if body is not None else None
    headers: dict[str, str] = {"Content-Type": "application/json", "Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read()
            return json.loads(raw) if raw.strip() else {}
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")
        raise RuntimeError(f"HTTP {exc.code} {method} {url}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Connection error {method} {url}: {exc.reason}") from exc


# ── Credential persistence ────────────────────────────────────────────────────

class AgentState:
    """Loads and saves {agent_id, token} from a JSON file on disk."""

    def __init__(self, path: Path) -> None:
        self.path     = path
        self.agent_id: str | None = None
        self.token:    str | None = None

    def load(self) -> bool:
        if not self.path.exists():
            return False
        try:
            d = json.loads(self.path.read_text())
            self.agent_id = d["agent_id"]
            self.token    = d["token"]
            log.info("Loaded credentials for agent %s from %s", self.agent_id[:8], self.path)
            return True
        except (KeyError, json.JSONDecodeError) as exc:
            log.warning("Could not read state file %s: %s", self.path, exc)
            return False

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps({"agent_id": self.agent_id, "token": self.token}, indent=2))
        log.info("Credentials saved → %s", self.path)


# ── Scan worker (one per job, runs in its own thread) ─────────────────────────

class ScanWorker:
    """Executes a single scan job and streams events back to the controller."""

    def __init__(
        self,
        controller: str,
        agent_id:   str,
        token:      str,
        job_id:     str,
        config:     dict,
        stop_event: threading.Event,
    ) -> None:
        self.controller  = controller
        self.agent_id    = agent_id
        self.token       = token
        self.job_id      = job_id
        self.config      = config
        self.stop_event  = stop_event
        self._pending:   list[dict] = []
        self._lock       = threading.Lock()
        self._last_flush = time.time()

    def run(self) -> None:
        error_msg: str | None = None
        try:
            log.info("Job %s — scanning %s", self.job_id[:8], self.config.get("target"))
            self._execute()
        except InterruptedError:
            error_msg = "Agent stopped — scan interrupted."
            log.warning("Job %s interrupted.", self.job_id[:8])
        except Exception as exc:
            error_msg = str(exc)
            log.exception("Job %s failed: %s", self.job_id[:8], exc)
        finally:
            self._flush()                   # send remaining buffered events
            self._mark_complete(error_msg)  # tell controller we're done

    # ── Scan execution ────────────────────────────────────────────────────────

    def _execute(self) -> None:
        from src.json_bridge import run_streaming_scan
        cfg   = self.config
        ports = self._resolve_ports(cfg.get("ports", "quick"))

        run_streaming_scan(
            target       = cfg["target"],
            ports        = ports,
            timeout      = float(cfg.get("timeout", 2)),
            threads      = int(cfg.get("threads", 100)),
            do_tls       = bool(cfg.get("do_tls")     or cfg.get("do_full")),
            do_headers   = bool(cfg.get("do_headers") or cfg.get("do_full")),
            do_stack     = bool(cfg.get("do_stack")   or cfg.get("do_full")),
            do_dns       = bool(cfg.get("do_dns")     or cfg.get("do_full")),
            do_osint     = bool(cfg.get("do_osint")   or cfg.get("do_full")),
            do_probe     = bool(cfg.get("do_probe")   or cfg.get("do_full")),
            do_takeover  = bool(cfg.get("do_takeover") or cfg.get("do_full")),
            do_full      = bool(cfg.get("do_full", False)),
            cidr         = bool(cfg.get("cidr", False)),
            min_cvss     = float(cfg.get("min_cvss", 4.0)),
            emit_callback= self._emit,
        )

    def _emit(self, event_type: str, data, message: str | None) -> None:
        """Called by the scan engine for every emitted event."""
        if self.stop_event.is_set():
            raise InterruptedError("Agent stopping.")

        event: dict = {"type": event_type}
        if message is not None:
            event["message"] = message
        else:
            event["data"] = data

        with self._lock:
            self._pending.append(event)
            should_flush = (
                len(self._pending) >= EVENT_BATCH_SIZE
                or (time.time() - self._last_flush) >= EVENT_FLUSH_SECS
            )
        if should_flush:
            self._flush()

    # ── Event flushing ────────────────────────────────────────────────────────

    def _flush(self) -> None:
        with self._lock:
            batch, self._pending = list(self._pending), []
            self._last_flush = time.time()
        if not batch:
            return
        url = f"{self.controller}/agents/{self.agent_id}/tasks/{self.job_id}/events"
        try:
            _http("POST", url, body=batch, token=self.token)
            log.debug("Flushed %d event(s) for job %s", len(batch), self.job_id[:8])
        except Exception as exc:
            log.warning("Failed to flush events (job %s): %s", self.job_id[:8], exc)

    def _mark_complete(self, error: str | None) -> None:
        url = f"{self.controller}/agents/{self.agent_id}/tasks/{self.job_id}/complete"
        try:
            _http("POST", url, body={"error": error}, token=self.token)
            log.info("Job %s → %s", self.job_id[:8], "failed" if error else "completed")
        except Exception as exc:
            log.warning("Failed to mark job %s complete: %s", self.job_id[:8], exc)

    # ── Port resolver ─────────────────────────────────────────────────────────

    @staticmethod
    def _resolve_ports(ports_arg: str) -> list[int]:
        from src.scanner import COMMON_PORTS, EXTENDED_PORTS
        if ports_arg == "quick":
            return list(COMMON_PORTS)
        if ports_arg == "full":
            return list(EXTENDED_PORTS)
        raw = ports_arg[len("custom="):]
        return [int(p) for p in raw.split(",") if p.strip().isdigit()]


# ── Agent orchestrator ────────────────────────────────────────────────────────

class NetLogicAgent:
    def __init__(
        self,
        controller:    str,
        state:         AgentState,
        hostname:      str,
        tags:          dict[str, str],
        concurrency:   int,
        poll_interval: float,
    ) -> None:
        self.controller    = controller.rstrip("/")
        self.state         = state
        self.hostname      = hostname
        self.tags          = tags
        self.concurrency   = concurrency
        self.poll_interval = poll_interval
        self._stop         = threading.Event()
        self._workers:     set[threading.Thread] = set()
        self._wlock        = threading.Lock()

    # ── One-time registration ─────────────────────────────────────────────────

    def register(self, api_key: str) -> None:
        """Exchange API key for JWT, register agent, persist credentials."""
        log.info("Obtaining JWT from %s …", self.controller)
        resp = _http("POST", f"{self.controller}/auth/token", body={"api_key": api_key})
        jwt  = resp["token"]

        log.info("Registering as '%s' …", self.hostname)
        resp = _http(
            "POST", f"{self.controller}/agents/register",
            token=jwt,
            body={
                "hostname":     self.hostname,
                "capabilities": CAPABILITIES,
                "version":      AGENT_VERSION,
                "tags":         self.tags,
            },
        )
        self.state.agent_id = resp["agent_id"]
        self.state.token    = resp["token"]
        self.state.save()
        log.info("Registered — agent_id: %s", self.state.agent_id)

    # ── Heartbeat thread ──────────────────────────────────────────────────────

    def _heartbeat_loop(self) -> None:
        url = f"{self.controller}/agents/{self.state.agent_id}/heartbeat"
        while not self._stop.is_set():
            try:
                _http("POST", url, token=self.state.token)
                log.debug("♥ heartbeat")
            except Exception as exc:
                log.warning("Heartbeat failed: %s", exc)
            self._stop.wait(HEARTBEAT_INTERVAL)

    # ── Worker tracking ───────────────────────────────────────────────────────

    def _active_count(self) -> int:
        with self._wlock:
            self._workers = {t for t in self._workers if t.is_alive()}
            return len(self._workers)

    def _start_worker(self, job_id: str, config: dict) -> None:
        worker = ScanWorker(
            controller = self.controller,
            agent_id   = self.state.agent_id,
            token      = self.state.token,
            job_id     = job_id,
            config     = config,
            stop_event = self._stop,
        )
        t = threading.Thread(target=worker.run, name=f"scan-{job_id[:8]}", daemon=True)
        with self._wlock:
            self._workers.add(t)
        t.start()

    # ── Main poll loop ────────────────────────────────────────────────────────

    def run(self) -> None:
        hb = threading.Thread(target=self._heartbeat_loop, name="heartbeat", daemon=True)
        hb.start()

        log.info("Agent ready. Controller: %s | Concurrency: %d | Poll: %ss",
                 self.controller, self.concurrency, self.poll_interval)

        url = f"{self.controller}/agents/{self.state.agent_id}/tasks"
        while not self._stop.is_set():
            if self._active_count() < self.concurrency:
                try:
                    tasks: list[dict] = _http("GET", url, token=self.state.token)
                    for task in tasks:
                        log.info("Dispatching job %s ← %s",
                                 task["job_id"][:8], task["config"].get("target"))
                        self._start_worker(task["job_id"], task["config"])
                except Exception as exc:
                    log.warning("Poll error: %s", exc)
            self._stop.wait(self.poll_interval)

        # Drain active scans before exiting
        log.info("Stopping — waiting for %d active scan(s) to finish …", self._active_count())
        deadline = time.time() + 120
        for t in list(self._workers):
            remaining = max(0.0, deadline - time.time())
            t.join(timeout=remaining)
        log.info("Agent stopped.")

    def stop(self) -> None:
        self._stop.set()


# ── CLI entry point ───────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="netlogic_agent",
        description="NetLogic Remote Agent — registers with a controller and runs scans.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--controller",
        default=os.environ.get("NETLOGIC_CONTROLLER", "http://localhost:8000"),
        metavar="URL",
        help="Controller base URL  (default: http://localhost:8000, or $NETLOGIC_CONTROLLER)",
    )
    parser.add_argument(
        "--api-key",
        default=os.environ.get("NETLOGIC_API_KEY"),
        metavar="KEY",
        help="API key — required only on the first run to register this agent",
    )
    parser.add_argument(
        "--name",
        default=socket.gethostname(),
        metavar="HOSTNAME",
        help="Override the reported hostname  (default: system hostname)",
    )
    parser.add_argument(
        "--tags",
        nargs="*",
        default=[],
        metavar="KEY=VALUE",
        help="Arbitrary metadata tags, e.g.  --tags env=prod region=us-east-1",
    )
    parser.add_argument(
        "--state",
        default=str(Path.home() / ".netlogic" / "agent.json"),
        metavar="FILE",
        help="Path to persist agent credentials  (default: ~/.netlogic/agent.json)",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=1,
        metavar="N",
        help="Maximum parallel scans this agent will run  (default: 1)",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=POLL_INTERVAL_IDLE,
        metavar="SECS",
        help=f"Task poll interval in seconds  (default: {POLL_INTERVAL_IDLE})",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Debug logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s  %(levelname)-7s %(message)s",
        datefmt="%H:%M:%S",
    )

    # Parse --tags key=value pairs
    tags: dict[str, str] = {}
    for item in args.tags or []:
        if "=" in item:
            k, v = item.split("=", 1)
            tags[k.strip()] = v.strip()

    state = AgentState(Path(args.state))

    agent = NetLogicAgent(
        controller    = args.controller,
        state         = state,
        hostname      = args.name,
        tags          = tags,
        concurrency   = args.concurrency,
        poll_interval = args.poll_interval,
    )

    if not state.load():
        # First run — registration required
        if not args.api_key:
            log.error(
                "No saved credentials found at %s.\n"
                "Provide --api-key to register this agent with the controller.",
                args.state,
            )
            sys.exit(1)
        agent.register(args.api_key)
    else:
        log.info("Using saved credentials (agent %s)", state.agent_id)

    # Graceful shutdown on Ctrl-C or SIGTERM
    def _on_signal(signum, _frame):
        log.info("Signal %d received — shutting down …", signum)
        agent.stop()

    signal.signal(signal.SIGINT,  _on_signal)
    signal.signal(signal.SIGTERM, _on_signal)

    agent.run()


if __name__ == "__main__":
    main()
