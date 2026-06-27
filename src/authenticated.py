"""
NetLogic - Authenticated Scanning (SSH package enumeration)
===========================================================
The cure for version-guessing. An unauthenticated banner ("OpenSSH 7.6") is a
guess; the installed PACKAGE version ("1:7.6p1-4ubuntu0.7") is the patch-level
truth — and its distro suffix tells you whether security fixes were backported.
With credentials, NetLogic reads that ground truth instead of inferring it.

Uses the system `ssh` client (no third-party deps). Key-based auth is the default
and recommended path for an authorized assessment; password auth is supported when
`sshpass` is available. Read-only commands only.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Optional

_SEP = "===NETLOGIC_SEP==="

# One read-only command: OS release, kernel, and the installed package list via
# whichever package manager exists (Debian/Ubuntu, RHEL/CentOS, or Alpine).
_ENUM_CMD = (
    "cat /etc/os-release 2>/dev/null; echo '%s'; "
    "uname -a 2>/dev/null; echo '%s'; "
    "(dpkg-query -W -f='${Package} ${Version}\\n' 2>/dev/null "
    "|| rpm -qa --qf '%%{NAME} %%{VERSION}-%%{RELEASE}\\n' 2>/dev/null "
    "|| apk info -v 2>/dev/null)"
) % (_SEP, _SEP)


@dataclass
class AuthResult:
    host: str
    success: bool = False
    error: Optional[str] = None
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    kernel: Optional[str] = None
    packages: dict = field(default_factory=dict)        # name -> full distro version
    product_versions: dict = field(default_factory=dict)  # netlogic product -> {upstream, full, backported}


# Installed package name → NetLogic product key.
_PACKAGE_TO_PRODUCT = {
    "openssh-server": "openssh", "openssh": "openssh", "openssh-clients": "openssh",
    "apache2": "apache", "httpd": "apache", "apache2-bin": "apache",
    "nginx": "nginx", "nginx-core": "nginx",
    "openssl": "openssl", "libssl1.1": "openssl", "libssl3": "openssl", "libssl-dev": "openssl",
    "mysql-server": "mysql", "mysql-community-server": "mysql",
    "mariadb-server": "mariadb",
    "postgresql": "postgresql",
    "redis-server": "redis", "redis": "redis",
    "vsftpd": "vsftpd", "proftpd-basic": "proftpd", "proftpd": "proftpd",
    "samba": "samba", "smbd": "samba",
    "php": "php", "php-fpm": "php", "php7.4-fpm": "php", "php8.1-fpm": "php",
    "exim4": "exim", "exim": "exim", "postfix": "postfix", "dovecot-core": "dovecot",
    "bind9": "bind", "named": "bind",
    "tomcat9": "tomcat", "tomcat": "tomcat",
    "docker-ce": "docker", "docker.io": "docker",
    "sudo": "sudo", "bash": "bash", "glibc": "glibc", "libc6": "glibc",
}

# Distro markers in a version string that indicate backported security patches.
_BACKPORT_SUFFIX = re.compile(r"(ubuntu|deb|\+deb|~deb|\.el\d|el\d|amzn|rhel|centos|\.fc\d|build|alpine|r\d+$)", re.I)


def _upstream_version(distro_version: str) -> str:
    """Strip the Debian epoch and distro packaging suffix → upstream version.

    '1:7.6p1-4ubuntu0.7' → '7.6p1'   '2.4.7-1ubuntu4.22' → '2.4.7'
    """
    v = distro_version.split(":", 1)[-1]      # drop epoch "1:"
    v = v.rsplit("-", 1)[0]                    # drop "-Nubuntu..." packaging revision
    v = v.split("+", 1)[0].split("~", 1)[0]    # drop "+debX" / "~"
    return v.strip()


def _parse_enum(stdout: str) -> dict:
    parts = stdout.split(_SEP)
    out = {"os_name": None, "os_version": None, "kernel": None, "packages": {}}
    if len(parts) >= 1:
        for line in parts[0].splitlines():
            if line.startswith("PRETTY_NAME="):
                out["os_name"] = line.split("=", 1)[1].strip().strip('"')
            elif line.startswith("VERSION_ID="):
                out["os_version"] = line.split("=", 1)[1].strip().strip('"')
    if len(parts) >= 2:
        out["kernel"] = parts[1].strip() or None
    if len(parts) >= 3:
        for line in parts[2].splitlines():
            line = line.strip()
            if not line:
                continue
            # dpkg/rpm: "name version"; apk: "name-version"
            m = re.match(r"^(\S+)\s+(\S+)$", line)
            if m:
                out["packages"][m.group(1)] = m.group(2)
            else:
                am = re.match(r"^(.+)-(\d[\w.\-+~]*)$", line)
                if am:
                    out["packages"][am.group(1)] = am.group(2)
    return out


def _map_products(packages: dict) -> dict:
    product_versions = {}
    for pkg, ver in packages.items():
        product = _PACKAGE_TO_PRODUCT.get(pkg.lower())
        if not product or product in product_versions:
            continue
        product_versions[product] = {
            "upstream": _upstream_version(ver),
            "full": ver,
            "backported": bool(_BACKPORT_SUFFIX.search(ver)),
        }
    return product_versions


def _rejects_option_injection(value: str) -> bool:
    """True if a value is unsafe to place in the ssh argv.

    ssh parses any argument starting with '-' as an option, so a crafted user /
    host / key path like '-oProxyCommand=…' becomes arbitrary code execution on
    the SCANNING host (argument injection — the ssh equivalent of shell injection).
    Reject anything that leads with '-' or carries whitespace/control chars, which
    a legitimate username, hostname, or path never needs.
    """
    if not value:
        return False
    if value[0] == "-":
        return True
    return any(c.isspace() or ord(c) < 0x20 for c in value)


def ssh_enumerate(host: str, user: str, key_path: Optional[str] = None,
                  password: Optional[str] = None, port: int = 22,
                  timeout: int = 20) -> AuthResult:
    """SSH in and enumerate installed package versions. Read-only, fail-soft."""
    result = AuthResult(host=host)

    # Defense-in-depth (covers the CLI path that bypasses the API's pydantic
    # validation): never let a value that ssh would parse as an option reach argv.
    for label, value in (("host", host), ("ssh user", user), ("ssh key path", key_path or "")):
        if _rejects_option_injection(value):
            result.error = f"Refusing authenticated scan: {label} contains unsafe characters."
            return result

    base = [
        "ssh",
        "-o", "BatchMode=yes" if not password else "BatchMode=no",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", f"ConnectTimeout={max(5, timeout - 5)}",
        "-p", str(port),
    ]
    if key_path:
        base += ["-i", key_path]
    cmd = base + [f"{user}@{host}", _ENUM_CMD]

    if password:
        if not shutil.which("sshpass"):
            result.error = "Password auth requires 'sshpass' (not found). Use key-based auth (--ssh-key)."
            return result
        env = {**os.environ, "SSHPASS": password}
        cmd = ["sshpass", "-e"] + cmd

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5, env=env)
    except subprocess.TimeoutExpired:
        result.error = "SSH connection timed out."
        return result
    except OSError as e:
        result.error = f"SSH not available: {e}"
        return result

    if proc.returncode != 0:
        err = (proc.stderr or "").strip().splitlines()
        result.error = f"SSH failed (exit {proc.returncode}): {err[-1] if err else 'unknown'}"
        return result

    parsed = _parse_enum(proc.stdout or "")
    result.success = bool(parsed["packages"])
    result.os_name = parsed["os_name"]
    result.os_version = parsed["os_version"]
    result.kernel = parsed["kernel"]
    result.packages = parsed["packages"]
    result.product_versions = _map_products(parsed["packages"])
    if not result.success:
        result.error = result.error or "Connected but no package data returned."
    return result
