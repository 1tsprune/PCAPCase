from __future__ import annotations

from pcapcase.models import Finding, Host, NetworkEvent

from .common import finding_from_events, is_private_ip

UPLOAD_METHODS = {"POST", "PUT", "PATCH"}
FILE_HINTS = ("multipart/form-data", "filename=", "Content-Disposition", "upload", "file=")


def detect(events: list[NetworkEvent], hosts: list[Host]) -> list[Finding]:
    """Detect HTTP upload / possible exfiltration.

    False positives: normal web forms, REST APIs, telemetry, backups, cloud
    sync, software crash reports, and admin uploads. Findings are phrased as
    possible exfiltration unless large/file-like external uploads are observed.
    """
    findings: list[Finding] = []
    for event in sorted(events, key=lambda e: (e.timestamp, e.frame_number)):
        if event.protocol != "http" or event.event_type != "http_request":
            continue
        method = (event.raw.get("http.request.method") or "").upper()
        if method not in UPLOAD_METHODS:
            continue
        uri = event.raw.get("http.request.full_uri") or ""
        content_type = event.raw.get("http.content_type") or ""
        content_length = _int(event.raw.get("http.content_length")) or 0
        combined = " ".join([uri, content_type, event.summary, *event.raw.values()])
        file_like = any(hint.lower() in combined.lower() for hint in FILE_HINTS)
        external = not is_private_ip(event.dst_ip)
        if not external and not file_like and content_length < 1024 * 1024:
            continue
        severity = "high" if external and (file_like or content_length >= 5 * 1024 * 1024) else "medium" if external else "low"
        confidence = "high" if external and file_like else "medium"
        findings.append(
            finding_from_events(
                "http-exfil",
                "HTTP upload / possible exfiltration",
                f"HTTP {method} upload-like request observed toward {event.dst_ip or 'unknown destination'}; file_like={file_like}, content_length={content_length}.",
                severity,
                confidence,
                "exfiltration",
                [event],
                "http.request.method",
                method,
                ["Validate whether this upload matches expected application behavior.", "Review request destination, user agent, size, and adjacent DNS/TLS events."],
                [{"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration", "confidence": "medium"}],
            )
        )
    return findings


def _int(value: str | None) -> int | None:
    try:
        return int(value) if value not in (None, "") else None
    except ValueError:
        return None
