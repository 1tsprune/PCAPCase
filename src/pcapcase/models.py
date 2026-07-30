from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

Severity = Literal["critical", "high", "medium", "low", "info"]
Confidence = Literal["high", "medium", "low"]
IndicatorType = Literal["ip", "domain", "url", "hash", "filename", "user_agent", "sni"]


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    text = value.strip()
    if not text:
        return None
    if _looks_like_epoch(text):
        return datetime.fromtimestamp(float(text), tz=timezone.utc)
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        normalized = _normalize_tshark_utc_time(text)
        for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%b %d, %Y %H:%M:%S.%f UTC", "%b %d, %Y %H:%M:%S UTC"):
            try:
                parsed = datetime.strptime(normalized, fmt)
                break
            except ValueError:
                continue
        else:
            raise
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).replace(microsecond=parsed.microsecond)


def _looks_like_epoch(text: str) -> bool:
    return bool(re.fullmatch(r"\d+(?:\.\d+)?", text))


def _normalize_tshark_utc_time(text: str) -> str:
    normalized = re.sub(r"\s+", " ", text.strip())
    match = re.search(r"(\d{2}:\d{2}:\d{2})\.(\d+)( UTC)$", normalized)
    if match and len(match.group(2)) > 6:
        normalized = normalized[: match.start(2)] + match.group(2)[:6] + normalized[match.end(2) :]
    return normalized


def format_datetime(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def to_jsonable(value: Any) -> Any:
    if isinstance(value, datetime):
        return format_datetime(value)
    if isinstance(value, Path):
        return str(value)
    if is_dataclass(value):
        return {k: to_jsonable(v) for k, v in asdict(value).items()}
    if isinstance(value, dict):
        return {str(k): to_jsonable(v) for k, v in sorted(value.items(), key=lambda item: str(item[0]))}
    if isinstance(value, (list, tuple, set)):
        return [to_jsonable(v) for v in value]
    return value


@dataclass(frozen=True)
class Evidence:
    frame_number: int
    timestamp: datetime
    protocol: str
    tcp_stream: int | None
    field: str
    value: str
    reproduction_command: str

    def to_dict(self) -> dict[str, Any]:
        return to_jsonable(self)


@dataclass(frozen=True)
class Finding:
    id: str
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    category: str
    first_seen: datetime
    last_seen: datetime
    source_hosts: list[str]
    destination_hosts: list[str]
    evidence: list[Evidence]
    recommendations: list[str]
    mitre_attack: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return to_jsonable(self)


@dataclass(frozen=True)
class NetworkEvent:
    timestamp: datetime
    event_type: str
    src_ip: str | None
    src_port: int | None
    dst_ip: str | None
    dst_port: int | None
    protocol: str
    summary: str
    frame_number: int
    stream_id: int | None
    raw: dict[str, str]

    def to_dict(self) -> dict[str, Any]:
        return to_jsonable(self)


@dataclass(frozen=True)
class Indicator:
    type: IndicatorType
    value: str
    first_seen: datetime
    last_seen: datetime
    source: str
    evidence: list[Evidence]

    def to_dict(self) -> dict[str, Any]:
        return to_jsonable(self)


@dataclass(frozen=True)
class Host:
    ip: str
    mac_addresses: list[str] = field(default_factory=list)
    hostnames: list[str] = field(default_factory=list)
    protocols: list[str] = field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    sent_events: int = 0
    received_events: int = 0

    def to_dict(self) -> dict[str, Any]:
        return to_jsonable(self)


@dataclass(frozen=True)
class CaptureMetadata:
    path: str
    sha256: str
    tshark_version: str | None
    frame_count: int | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    duration_seconds: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return to_jsonable(self)


@dataclass(frozen=True)
class ExtractedObject:
    sha256: str
    original_filename: str
    sanitized_filename: str
    size: int
    source_frame: int | None
    tcp_stream: int | None
    extraction_timestamp: datetime
    path: str
    yara_matches: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return to_jsonable(self)


@dataclass(frozen=True)
class RunMetadata:
    pcapcase_version: str
    started_at: datetime
    cli_args: list[str]
    tshark_version: str | None
    input_sha256: str | None
    output_directory: str | None

    def to_dict(self) -> dict[str, Any]:
        return to_jsonable(self)


@dataclass(frozen=True)
class CaseResult:
    capture: CaptureMetadata
    hosts: list[Host]
    events: list[NetworkEvent]
    indicators: list[Indicator]
    extracted_objects: list[ExtractedObject]
    findings: list[Finding]
    run: RunMetadata

    def to_dict(self) -> dict[str, Any]:
        return to_jsonable(self)
