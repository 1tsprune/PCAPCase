from __future__ import annotations

from pathlib import Path

from pcapcase.models import NetworkEvent, parse_datetime
from pcapcase.runner import TSharkRunner

FIELDS = ["frame.number", "frame.time_utc", "ip.src", "ip.dst", "icmp.type", "icmp.code"]


def parse(pcap_path: str | Path, runner: TSharkRunner) -> list[NetworkEvent]:
    rows, command = runner.fields(pcap_path, "icmp", FIELDS)
    events: list[NetworkEvent] = []
    for row in rows:
        timestamp = parse_datetime(row.get("frame.time_utc"))
        if timestamp is None:
            continue
        raw = dict(row)
        raw["_tshark_command"] = command
        typ = row.get("icmp.type") or ""
        events.append(NetworkEvent(timestamp, "icmp", row.get("ip.src") or None, None, row.get("ip.dst") or None, None, "icmp", f"ICMP type={typ}", int(row.get("frame.number") or 0), None, raw))
    return events
