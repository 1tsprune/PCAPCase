from __future__ import annotations

from pathlib import Path

from pcapcase.models import NetworkEvent, parse_datetime
from pcapcase.runner import TSharkRunner

FIELDS = ["frame.number", "frame.time_utc", "arp.src.hw_mac", "arp.src.proto_ipv4", "arp.dst.hw_mac", "arp.dst.proto_ipv4", "arp.opcode"]


def parse(pcap_path: str | Path, runner: TSharkRunner) -> list[NetworkEvent]:
    rows, command = runner.fields(pcap_path, "arp", FIELDS)
    events: list[NetworkEvent] = []
    for row in rows:
        timestamp = parse_datetime(row.get("frame.time_utc"))
        if timestamp is None:
            continue
        raw = dict(row)
        raw["_tshark_command"] = command
        src = row.get("arp.src.proto_ipv4") or None
        dst = row.get("arp.dst.proto_ipv4") or None
        opcode = row.get("arp.opcode") or ""
        events.append(NetworkEvent(timestamp, "arp", src, None, dst, None, "arp", f"ARP opcode={opcode} {src}->{dst}", int(row.get("frame.number") or 0), None, raw))
    return events
