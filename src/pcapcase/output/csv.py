from __future__ import annotations

import csv
from pathlib import Path

from pcapcase.models import Host, NetworkEvent, format_datetime
from pcapcase.schema import HOSTS_CSV_HEADER, TIMELINE_CSV_HEADER


def write_timeline(path: str | Path, events: list[NetworkEvent]) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=TIMELINE_CSV_HEADER)
        writer.writeheader()
        for event in sorted(events, key=lambda e: (e.timestamp, e.frame_number, e.protocol)):
            writer.writerow({
                "timestamp": format_datetime(event.timestamp),
                "frame_number": event.frame_number,
                "protocol": event.protocol,
                "event_type": event.event_type,
                "src_ip": event.src_ip or "",
                "src_port": event.src_port or "",
                "dst_ip": event.dst_ip or "",
                "dst_port": event.dst_port or "",
                "stream_id": event.stream_id if event.stream_id is not None else "",
                "summary": event.summary,
            })


def write_hosts(path: str | Path, hosts: list[Host]) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=HOSTS_CSV_HEADER)
        writer.writeheader()
        for host in sorted(hosts, key=lambda h: h.ip):
            writer.writerow({
                "ip": host.ip,
                "mac_addresses": ";".join(host.mac_addresses),
                "hostnames": ";".join(host.hostnames),
                "protocols": ";".join(host.protocols),
                "first_seen": format_datetime(host.first_seen),
                "last_seen": format_datetime(host.last_seen),
                "sent_events": host.sent_events,
                "received_events": host.received_events,
            })
