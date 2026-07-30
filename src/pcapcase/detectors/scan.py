from __future__ import annotations

from pcapcase.models import Finding, Host, NetworkEvent

from .common import finding_from_events, group_by_source_window, unique_destinations, unique_ports


def detect(events: list[NetworkEvent], hosts: list[Host]) -> list[Finding]:
    return sorted([*detect_arp_sweeps(events, hosts), *detect_icmp_sweeps(events, hosts), *detect_tcp_port_scans(events, hosts)], key=lambda f: (f.first_seen, f.id))


def detect_arp_sweeps(events: list[NetworkEvent], hosts: list[Host]) -> list[Finding]:
    """Detect ARP sweeps.

    False positives: DHCP renewals, vulnerability scanners, asset inventory,
    network monitoring, and normal ARP bursts during host boot can look similar.
    The threshold favors many distinct target IPs in a short window to reduce
    alerts on routine neighbor discovery.
    """
    arp_requests = [e for e in events if e.protocol == "arp" and (e.raw.get("arp.opcode") in {"1", "request", ""})]
    findings: list[Finding] = []
    seen: set[tuple[str, int]] = set()
    for source, windows in group_by_source_window(arp_requests, 60).items():
        for window in windows:
            targets = unique_destinations(window)
            if len(targets) < 10:
                continue
            key = (source, min(event.frame_number for event in window))
            if key in seen:
                continue
            seen.add(key)
            severity = "medium" if len(targets) >= 25 else "low"
            confidence = "high" if len(targets) >= 25 else "medium"
            findings.append(
                finding_from_events(
                    "arp-sweep",
                    "ARP sweep detected",
                    f"Host {source} sent ARP requests for {len(targets)} distinct IPs within 60 seconds.",
                    severity,
                    confidence,
                    "internal-recon",
                    window,
                    "arp.dst.proto_ipv4",
                    f"{len(targets)} distinct targets",
                    ["Confirm whether the source is an approved scanner or inventory system.", "Review adjacent timeline events for follow-on connections."],
                    [{"id": "T1018", "name": "Remote System Discovery", "tactic": "Discovery", "confidence": "medium"}],
                )
            )
            break
    return findings


def detect_icmp_sweeps(events: list[NetworkEvent], hosts: list[Host]) -> list[Finding]:
    """Detect ICMP ping sweeps.

    False positives include monitoring systems, troubleshooting, uptime checks,
    and vulnerability scanners. Echo-request-only behavior with many distinct
    targets in a short window is required.
    """
    icmp_requests = [e for e in events if e.protocol == "icmp" and e.raw.get("icmp.type") in {"8", "echo", ""}]
    findings: list[Finding] = []
    seen_sources: set[str] = set()
    for source, windows in group_by_source_window(icmp_requests, 60).items():
        if source in seen_sources:
            continue
        for window in windows:
            targets = unique_destinations(window)
            if len(targets) < 10:
                continue
            seen_sources.add(source)
            severity = "medium" if len(targets) >= 30 else "low"
            confidence = "high" if len(targets) >= 30 else "medium"
            findings.append(
                finding_from_events(
                    "icmp-sweep",
                    "ICMP sweep detected",
                    f"Host {source} sent ICMP echo requests to {len(targets)} distinct IPs within 60 seconds.",
                    severity,
                    confidence,
                    "internal-recon",
                    window,
                    "icmp.type",
                    "echo-request sweep",
                    ["Validate whether this is approved monitoring or scanning.", "Pivot on the source host for TCP follow-up activity."],
                    [{"id": "T1018", "name": "Remote System Discovery", "tactic": "Discovery", "confidence": "medium"}],
                )
            )
            break
    return findings


def detect_tcp_port_scans(events: list[NetworkEvent], hosts: list[Host]) -> list[Finding]:
    """Detect TCP port scans.

    False positives include vulnerability scanners, service discovery,
    load balancer health checks, and failed application retries. The detector
    requires SYN-like connection attempts to many ports or hosts in 60 seconds.
    """
    syns = [e for e in events if e.protocol == "tcp" and e.raw.get("tcp.flags.syn") in {"1", "True", "true"} and e.raw.get("tcp.flags.ack") not in {"1", "True", "true"}]
    findings: list[Finding] = []
    seen_sources: set[str] = set()
    for source, windows in group_by_source_window(syns, 60).items():
        if source in seen_sources:
            continue
        for window in windows:
            ports = unique_ports(window)
            targets = unique_destinations(window)
            if len(ports) < 15 and len(targets) < 15:
                continue
            seen_sources.add(source)
            severity = "medium" if len(ports) >= 30 or len(targets) >= 30 else "low"
            confidence = "high" if len(ports) >= 30 or len(targets) >= 30 else "medium"
            findings.append(
                finding_from_events(
                    "tcp-scan",
                    "TCP port scan detected",
                    f"Host {source} attempted TCP connections across {len(ports)} ports and {len(targets)} destinations within 60 seconds.",
                    severity,
                    confidence,
                    "internal-recon",
                    window,
                    "tcp.flags.syn",
                    "SYN burst",
                    ["Check whether the source is an authorized scanner.", "Review destination services and any successful follow-up sessions."],
                    [{"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery", "confidence": "high"}],
                )
            )
            break
    return findings
