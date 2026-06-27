"""Sandbox for controlled exploit-proof execution.

Executes PoC scripts in a restricted subprocess with:
  - temp-directory filesystem isolation
  - configurable timeout
  - stdout/stderr/exit-code capture
  - cleanup after execution

Network restriction is best-effort documented; real network sandboxing
requires OS-level (firewall rules / container) which varies by platform.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class SandboxResult:
    success: bool = False
    stdout: str = ""
    stderr: str = ""
    exit_code: int = -1
    duration_ms: float = 0.0
    error: str = ""


def _find_python() -> str:
    """Return the Python interpreter path for the subprocess."""
    return sys.executable


def run_poc(script: str, target: str, timeout: int = 30) -> SandboxResult:
    """Execute a PoC script string against *target* in an isolated subprocess.

    Writes the script to a temp file, runs it with the target as an env var and
    CLI arg, captures output, and cleans up.
    """
    start = time.time()
    result = SandboxResult()

    tmp = Path(tempfile.mkdtemp(prefix="netlogic_poc_"))
    script_path = tmp / "poc.py"
    try:
        script_path.write_text(script, encoding="utf-8")
        env = {**os.environ, "POC_TARGET": target}
        proc = subprocess.run(
            [_find_python(), str(script_path), target],
            capture_output=True, text=True, timeout=timeout,
            cwd=str(tmp), env=env,
        )
        result.stdout = proc.stdout
        result.stderr = proc.stderr
        result.exit_code = proc.returncode
        result.success = proc.returncode == 0
    except subprocess.TimeoutExpired:
        result.error = f"timeout ({timeout}s)"
    except FileNotFoundError as e:
        result.error = f"python not found: {e}"
    except Exception as e:
        result.error = str(e)[:200]
    finally:
        try:
            for f in tmp.iterdir():
                f.unlink(missing_ok=True)
            tmp.rmdir()
        except OSError:
            pass

    result.duration_ms = (time.time() - start) * 1000
    return result


def run_poc_file(path: str, target: str, timeout: int = 30) -> SandboxResult:
    """Execute a PoC script file against *target*.

    The file is copied to a temp directory before execution so the original
    is never modified.
    """
    start = time.time()
    result = SandboxResult()

    tmp = Path(tempfile.mkdtemp(prefix="netlogic_poc_"))
    try:
        src = Path(path)
        if not src.exists():
            result.error = f"file not found: {path}"
            return result
        dst = tmp / src.name
        dst.write_bytes(src.read_bytes())
        dst.chmod(src.stat().st_mode)

        env = {**os.environ, "POC_TARGET": target}
        proc = subprocess.run(
            [_find_python(), str(dst), target],
            capture_output=True, text=True, timeout=timeout,
            cwd=str(tmp), env=env,
        )
        result.stdout = proc.stdout
        result.stderr = proc.stderr
        result.exit_code = proc.returncode
        result.success = proc.returncode == 0
    except subprocess.TimeoutExpired:
        result.error = f"timeout ({timeout}s)"
    except Exception as e:
        result.error = str(e)[:200]
    finally:
        try:
            for f in tmp.iterdir():
                f.unlink(missing_ok=True)
            tmp.rmdir()
        except OSError:
            pass

    result.duration_ms = (time.time() - start) * 1000
    return result


def gen_poc_http(
    subject: str, target: str, port: int,
    method: str = "GET", path: str = "/",
    headers: Optional[dict[str, str]] = None,
    body: Optional[str] = None,
    use_tls: bool = False,
    expected_pattern: str = "",
) -> str:
    """Generate a self-contained Python PoC script for an HTTP-based check.

    The returned script accepts an optional target CLI arg (defaults to *target*).
    """
    lines: list[str] = [
        '#!/usr/bin/env python3',
        f'"""PoC for {subject} on {{target}}:{port}"""',
        'import socket, ssl, sys',
        '',
        f'target = sys.argv[1] if len(sys.argv) > 1 else "{target}"',
        f'port = {port}',
        '',
        'def probe():',
        '    try:',
        f'        with socket.create_connection((target, port), timeout=10) as sock:',
    ]

    if use_tls:
        lines.extend([
            '            ctx = ssl.create_default_context()',
            '            ctx.check_hostname = False',
            '            ctx.verify_mode = ssl.CERT_NONE',
            '            with ctx.wrap_socket(sock, server_hostname=target) as s:',
            '                s.settimeout(10)',
        ])
    else:
        lines.append('            sock.settimeout(10)')

    var = "            s" if use_tls else "            sock"
    lines.append(f'{var}.sendall(b"{method} {path} HTTP/1.0\\r\\n")')
    lines.append(f'{var}.sendall(b"Host: {target}\\r\\n")')
    if headers:
        for k, v in headers.items():
            lines.append(f'{var}.sendall(b"{k}: {v}\\r\\n")')
    if body:
        escaped = body.replace("\\", "\\\\").replace('"', '\\"')
        lines.append(f'{var}.sendall(b"Content-Length: {len(body.encode())}\\r\\n")')
        lines.append(f'{var}.sendall(b"\\r\\n")')
        lines.append(f'{var}.sendall(b"{escaped}")')
    lines.append(f'{var}.sendall(b"Connection: close\\r\\n")')
    lines.append(f'{var}.sendall(b"\\r\\n")')
    lines.append(f'        resp = {var}.recv(65536)')
    lines.append('        text = resp.decode("utf-8", errors="replace")')
    lines.append('        print(text[:2000])')

    if expected_pattern:
        escaped = expected_pattern.replace('"', '\\"')
        lines.extend([
            f'        if "{escaped}" in text.lower():',
            f'            print("VULNERABLE: {subject} detected")',
            '            return 0',
            '        print("NOT VULNERABLE: pattern not found")',
            '        return 1',
        ])
    else:
        lines.extend([
            '        print("Probe sent")',
            '        return 0',
        ])

    lines.extend([
        '    except Exception as e:',
        '        print(f"ERROR: {e}")',
        '        return 2',
        '',
        'if __name__ == "__main__":',
        '    sys.exit(probe())',
    ])
    return "\n".join(lines) + "\n"


def gen_poc_connect(subject: str, target: str, port: int, use_tls: bool = False) -> str:
    """Generate a PoC script that only checks TCP/TLS connectivity."""
    lines: list[str] = [
        '#!/usr/bin/env python3',
        f'"""Connectivity PoC for {subject} on {{target}}:{port}"""',
        'import socket, ssl, sys',
        '',
        f'target = sys.argv[1] if len(sys.argv) > 1 else "{target}"',
        f'port = {port}',
        '',
        'def probe():',
        '    try:',
        f'        with socket.create_connection((target, port), timeout=10) as sock:',
    ]

    if use_tls:
        lines.extend([
            '            ctx = ssl.create_default_context()',
            '            ctx.check_hostname = False',
            '            ctx.verify_mode = ssl.CERT_NONE',
            '            with ctx.wrap_socket(sock, server_hostname=target) as s:',
            '                s.settimeout(5)',
            '                banner = s.recv(1024)',
            '        print(f"Connected — banner: {banner.decode(\'utf-8\', errors=\'replace\')[:200]}")',
        ])
    else:
        lines.extend([
            '            sock.settimeout(5)',
            '            banner = sock.recv(1024)',
            '        print(f"Connected — banner: {banner.decode(\'utf-8\', errors=\'replace\')[:200]}")',
        ])

    lines.extend([
        '        return 0',
        '    except Exception as e:',
        '        print(f"FAILED: {e}")',
        '        return 1',
        '',
        'if __name__ == "__main__":',
        '    sys.exit(probe())',
    ])
    return "\n".join(lines) + "\n"
