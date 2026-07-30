from __future__ import annotations

from pcapcase.models import Finding, Host, NetworkEvent

from . import credentials, download, exfiltration, scan


def run_all(events: list[NetworkEvent], hosts: list[Host]) -> list[Finding]:
    findings: list[Finding] = []
    for detector in (scan.detect, download.detect, exfiltration.detect, credentials.detect):
        findings.extend(detector(events, hosts))
    return sorted(findings, key=lambda item: (item.first_seen, item.id, item.title))
