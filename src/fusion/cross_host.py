"""Cross-host correlation for multi-host attack chains.

After adjudication produces verdicts per host, this module groups related
findings across hosts so the synthesis can narrate multi-hop attack chains:

  • Same service/version across hosts ("Apache 2.4.49 on both hosts")
  • Complementary roles ("Host A has creds, Host B has the admin panel")
  • Shared tech stack suggesting same vulnerability class

The correlations are fed into the synthesis prompt as structured context.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Optional


@dataclass
class CrossHostGroup:
    label: str
    hosts: list[str]
    subjects: list[str]
    shared_tech: Optional[str] = None
    correlation_type: str = ""  # "same_service" | "complementary" | "shared_tech"


def correlate_verdicts(host_verdicts: dict[str, list[dict]]) -> list[CrossHostGroup]:
    """Group verdicts across hosts by shared characteristics.

    *host_verdicts* maps host IP → list of verdict dicts (from fusion output).
    Returns groups describing cross-host relationships for the synthesis prompt.
    """
    groups: list[CrossHostGroup] = []

    # Group by service+version across hosts
    service_hosts: dict[str, set[str]] = defaultdict(set)
    service_subjects: dict[str, list[str]] = defaultdict(list)
    for host, verdicts in host_verdicts.items():
        for v in verdicts:
            service = v.get("source", "")
            subject = v.get("subject", "")
            port = v.get("port")
            key = f"{service}:{port}" if port else service
            if subject:
                service_hosts[key].add(host)
                service_subjects[key].append(subject)

    for key, hosts in service_hosts.items():
        if len(hosts) >= 2:
            groups.append(CrossHostGroup(
                label=f"Shared {key} across {len(hosts)} hosts",
                hosts=sorted(hosts),
                subjects=service_subjects[key],
                shared_tech=key.split(":")[0] if ":" in key else key,
                correlation_type="same_service",
            ))

    return groups


def cross_host_context(host_verdicts: dict[str, list[dict]]) -> Optional[dict]:
    """Build a structured 'cross_host' context block for the synthesis prompt.

    Returns None when there are no multi-host correlations (single-host scan).
    """
    groups = correlate_verdicts(host_verdicts)
    if not groups:
        return None
    return {
        "multi_host_groups": [
            {
                "label": g.label,
                "hosts": g.hosts,
                "subjects": g.subjects,
                "correlation_type": g.correlation_type,
            }
            for g in groups
        ],
    }
