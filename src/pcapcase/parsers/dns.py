from __future__ import annotations

from pathlib import Path

from pcapcase.models import NetworkEvent, parse_datetime
from pcapcase.runner import TSharkRunner

FIELDS = ["frame.number", "frame.time_utc", "ip.src", "udp.srcport", "ip.dst", "udp.dstport", "dns.qry.name", "dns.a", "dns.resp.name"]


def parse(pcap_path: str | Path, runner: TSharkRunner) -> list[NetworkEvent]:
    rows, command = runner.fields(pcap_path, "dns", FIELDS)
    events: list[NetworkEvent] = []
    for row in rows:
        timestamp = parse_datetime(row.get("frame.time_utc"))
        if timestamp is None:
            continue
        query = row.get("dns.qry.name") or row.get("dns.resp.name") or ""
        answer = row.get("dns.a") or ""
        raw = dict(row)
        raw["_tshark_command"] = command
        events.append(NetworkEvent(timestamp, "dns", row.get("ip.src") or None, _int(row.get("udp.srcport")), row.get("ip.dst") or None, _int(row.get("udp.dstport")), "dns", f"DNS {query} {answer}".strip(), int(row.get("frame.number") or 0), None, raw))
    return events


def _int(value: str | None) -> int | None:
    try:
        return int(value) if value not in (None, "") else None
    except ValueError:
        return None
