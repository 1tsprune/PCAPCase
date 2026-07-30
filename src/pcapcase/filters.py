from __future__ import annotations

from datetime import datetime

from .models import NetworkEvent


def filter_events(
    events: list[NetworkEvent],
    host: str | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
    protocols: set[str] | None = None,
) -> list[NetworkEvent]:
    protocol_set = {item.lower() for item in protocols} if protocols else None
    result: list[NetworkEvent] = []
    for event in events:
        if host and event.src_ip != host and event.dst_ip != host:
            continue
        if start and event.timestamp < start:
            continue
        if end and event.timestamp > end:
            continue
        if protocol_set and event.protocol.lower() not in protocol_set:
            continue
        result.append(event)
    return sorted(result, key=lambda e: (e.timestamp, e.frame_number, e.protocol, e.event_type))


def parse_protocols(value: str | None) -> set[str] | None:
    if not value:
        return None
    protocols = {part.strip().lower() for part in value.split(",") if part.strip()}
    if not protocols:
        return None
    allowed = {"dns", "http", "tls", "arp", "icmp", "tcp"}
    unknown = protocols - allowed
    if unknown:
        raise ValueError(f"unsupported protocol filter(s): {', '.join(sorted(unknown))}")
    return protocols
