from __future__ import annotations

from pathlib import Path

from pcapcase.models import NetworkEvent, parse_datetime
from pcapcase.runner import TSharkRunner

FIELDS = ["frame.number", "frame.time_utc", "ip.src", "tcp.srcport", "ip.dst", "tcp.dstport", "tcp.stream", "tcp.flags.syn", "tcp.flags.ack", "tcp.flags.reset"]


def parse(pcap_path: str | Path, runner: TSharkRunner) -> list[NetworkEvent]:
    rows, command = runner.fields(pcap_path, "tcp", FIELDS)
    events: list[NetworkEvent] = []
    for row in rows:
        timestamp = parse_datetime(row.get("frame.time_utc"))
        if timestamp is None:
            continue
        raw = dict(row)
        raw["_tshark_command"] = command
        flags = f"syn={row.get('tcp.flags.syn') or '0'} ack={row.get('tcp.flags.ack') or '0'} rst={row.get('tcp.flags.reset') or '0'}"
        events.append(NetworkEvent(timestamp, "tcp", row.get("ip.src") or None, _int(row.get("tcp.srcport")), row.get("ip.dst") or None, _int(row.get("tcp.dstport")), "tcp", f"TCP {flags}", int(row.get("frame.number") or 0), _int(row.get("tcp.stream")), raw))
    return events


def _int(value: str | None) -> int | None:
    try:
        return int(value) if value not in (None, "") else None
    except ValueError:
        return None
