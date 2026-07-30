from __future__ import annotations

from pathlib import Path

from pcapcase.models import NetworkEvent, parse_datetime
from pcapcase.runner import TSharkRunner

FIELDS = ["frame.number", "frame.time_utc", "ip.src", "tcp.srcport", "ip.dst", "tcp.dstport", "tcp.stream", "tls.handshake.extensions_server_name"]


def parse(pcap_path: str | Path, runner: TSharkRunner) -> list[NetworkEvent]:
    rows, command = runner.fields(pcap_path, "tls", FIELDS)
    events: list[NetworkEvent] = []
    for row in rows:
        timestamp = parse_datetime(row.get("frame.time_utc"))
        if timestamp is None:
            continue
        sni = row.get("tls.handshake.extensions_server_name") or ""
        raw = dict(row)
        raw["_tshark_command"] = command
        events.append(NetworkEvent(timestamp, "tls", row.get("ip.src") or None, _int(row.get("tcp.srcport")), row.get("ip.dst") or None, _int(row.get("tcp.dstport")), "tls", f"TLS SNI {sni}".strip(), int(row.get("frame.number") or 0), _int(row.get("tcp.stream")), raw))
    return events


def _int(value: str | None) -> int | None:
    try:
        return int(value) if value not in (None, "") else None
    except ValueError:
        return None
