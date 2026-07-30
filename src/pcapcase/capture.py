from __future__ import annotations

from pathlib import Path

from .models import CaptureMetadata, parse_datetime
from .runner import TSharkRunner, sha256_file


def read_capture_metadata(path: str | Path, runner: TSharkRunner) -> CaptureMetadata:
    pcap = Path(path)
    digest = sha256_file(pcap)
    tshark_version: str | None
    try:
        tshark_version = runner.version()
    except Exception:
        tshark_version = None
    frame_count = None
    first_seen = None
    last_seen = None
    try:
        rows, _ = runner.fields(pcap, "frame", ["frame.number", "frame.time_epoch", "frame.time_utc"])
        frame_count = len(rows)
        times = []
        for row in rows:
            time_value = row.get("frame.time_utc") or ""
            try:
                parsed = parse_datetime(time_value)
            except Exception:
                parsed = None
            if parsed:
                times.append(parsed)
        if times:
            first_seen = min(times)
            last_seen = max(times)
    except Exception:
        pass
    duration = (last_seen - first_seen).total_seconds() if first_seen and last_seen else None
    return CaptureMetadata(str(pcap), digest, tshark_version, frame_count, first_seen, last_seen, duration)
