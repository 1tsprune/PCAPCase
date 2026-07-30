from __future__ import annotations

import hashlib
import ipaddress
from collections import defaultdict
from datetime import timedelta
from typing import Iterable

from pcapcase.models import Evidence, Finding, Host, NetworkEvent


def is_private_ip(value: str | None) -> bool:
    if not value:
        return False
    try:
        return ipaddress.ip_address(value).is_private
    except ValueError:
        return False


def finding_id(prefix: str, events: Iterable[NetworkEvent], extra: str = "") -> str:
    material = "|".join(str(event.frame_number) for event in sorted(events, key=lambda e: e.frame_number)) + "|" + extra
    return f"{prefix}-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:12]}"


def evidence_from_event(event: NetworkEvent, field: str, value: str) -> Evidence:
    command = event.raw.get("_tshark_command") or f'tshark -r <pcap> -Y "frame.number=={event.frame_number}" -T fields -e frame.number'
    return Evidence(event.frame_number, event.timestamp, event.protocol, event.stream_id, field, value, command)


def group_by_source_window(events: list[NetworkEvent], seconds: int) -> dict[str, list[list[NetworkEvent]]]:
    grouped: dict[str, list[NetworkEvent]] = defaultdict(list)
    for event in sorted(events, key=lambda e: (e.src_ip or "", e.timestamp, e.frame_number)):
        if event.src_ip:
            grouped[event.src_ip].append(event)
    windows: dict[str, list[list[NetworkEvent]]] = defaultdict(list)
    delta = timedelta(seconds=seconds)
    for source, source_events in grouped.items():
        start = 0
        for end, event in enumerate(source_events):
            while event.timestamp - source_events[start].timestamp > delta:
                start += 1
            window = source_events[start : end + 1]
            windows[source].append(window)
    return windows


def unique_destinations(events: Iterable[NetworkEvent]) -> set[str]:
    return {event.dst_ip for event in events if event.dst_ip}


def unique_ports(events: Iterable[NetworkEvent]) -> set[int]:
    return {event.dst_port for event in events if event.dst_port is not None}


def host_set(events: Iterable[NetworkEvent], attr: str) -> list[str]:
    values = {getattr(event, attr) for event in events if getattr(event, attr)}
    return sorted(values)


def finding_from_events(
    prefix: str,
    title: str,
    description: str,
    severity: str,
    confidence: str,
    category: str,
    events: list[NetworkEvent],
    field: str,
    value: str,
    recommendations: list[str],
    mitre_attack: list[dict[str, str]] | None = None,
) -> Finding:
    ordered = sorted(events, key=lambda e: (e.timestamp, e.frame_number))
    return Finding(
        id=finding_id(prefix, ordered, title),
        title=title,
        description=description,
        severity=severity,  # type: ignore[arg-type]
        confidence=confidence,  # type: ignore[arg-type]
        category=category,
        first_seen=ordered[0].timestamp,
        last_seen=ordered[-1].timestamp,
        source_hosts=host_set(ordered, "src_ip"),
        destination_hosts=host_set(ordered, "dst_ip"),
        evidence=[evidence_from_event(event, field, value) for event in ordered[:10]],
        recommendations=recommendations,
        mitre_attack=mitre_attack or [],
    )
