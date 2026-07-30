from __future__ import annotations

from pathlib import Path

from pcapcase.models import NetworkEvent, parse_datetime
from pcapcase.redaction import Redactor
from pcapcase.runner import TSharkRunner

FIELDS = [
    "frame.number",
    "frame.time_utc",
    "ip.src",
    "tcp.srcport",
    "ip.dst",
    "tcp.dstport",
    "tcp.stream",
    "http.request.method",
    "http.request.full_uri",
    "http.host",
    "http.user_agent",
    "http.response.code",
    "http.content_type",
    "http.content_length",
    "http.file_data",
    "urlencoded-form.key",
    "urlencoded-form.value",
]


def parse(pcap_path: str | Path, runner: TSharkRunner, redactor: Redactor) -> list[NetworkEvent]:
    rows, command = runner.fields(pcap_path, "http", FIELDS)
    events: list[NetworkEvent] = []
    for row in rows:
        timestamp = parse_datetime(row.get("frame.time_utc"))
        if timestamp is None:
            continue
        frame = int(row.get("frame.number") or 0)
        method = row.get("http.request.method") or ""
        uri = redactor.redact(row.get("http.request.full_uri") or "")
        code = row.get("http.response.code") or ""
        host = row.get("http.host") or ""
        user_agent = redactor.redact(row.get("http.user_agent") or "")
        event_type = "http_request" if method else "http_response" if code else "http"
        summary = f"{method} {uri}".strip() if method else f"HTTP {code} {row.get('http.content_type') or ''}".strip()
        raw = {key: redactor.redact(value) for key, value in row.items()}
        raw["_tshark_command"] = command
        raw["_host"] = host
        raw["_user_agent"] = user_agent
        events.append(
            NetworkEvent(
                timestamp=timestamp,
                event_type=event_type,
                src_ip=row.get("ip.src") or None,
                src_port=_int_or_none(row.get("tcp.srcport")),
                dst_ip=row.get("ip.dst") or None,
                dst_port=_int_or_none(row.get("tcp.dstport")),
                protocol="http",
                summary=summary,
                frame_number=frame,
                stream_id=_int_or_none(row.get("tcp.stream")),
                raw=raw,
            )
        )
    return events


def _int_or_none(value: str | None) -> int | None:
    try:
        return int(value) if value not in (None, "") else None
    except ValueError:
        return None
