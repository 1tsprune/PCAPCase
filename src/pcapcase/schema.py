from __future__ import annotations

from typing import Any

SCHEMA_VERSION = "1.0"

FINDING_REQUIRED_FIELDS = {
    "id",
    "title",
    "description",
    "severity",
    "confidence",
    "category",
    "first_seen",
    "last_seen",
    "source_hosts",
    "destination_hosts",
    "evidence",
    "recommendations",
    "mitre_attack",
}

EVIDENCE_REQUIRED_FIELDS = {
    "frame_number",
    "timestamp",
    "protocol",
    "tcp_stream",
    "field",
    "value",
    "reproduction_command",
}

INDICATOR_REQUIRED_FIELDS = {
    "type",
    "value",
    "first_seen",
    "last_seen",
    "source",
    "evidence",
}

CASE_REQUIRED_FIELDS = {
    "capture",
    "hosts",
    "events",
    "indicators",
    "extracted_objects",
    "findings",
    "run",
}

CAPTURE_REQUIRED_FIELDS = {
    "path",
    "sha256",
    "tshark_version",
    "frame_count",
    "first_seen",
    "last_seen",
    "duration_seconds",
}

RUN_REQUIRED_FIELDS = {
    "pcapcase_version",
    "started_at",
    "cli_args",
    "tshark_version",
    "input_sha256",
    "output_directory",
}

EXTRACTED_MANIFEST_REQUIRED_FIELDS = {"schema_version", "objects"}
EXTRACTED_OBJECT_REQUIRED_FIELDS = {
    "sha256",
    "original_filename",
    "sanitized_filename",
    "size",
    "source_frame",
    "tcp_stream",
    "extraction_timestamp",
    "path",
    "yara_matches",
}

HOSTS_CSV_HEADER = [
    "ip",
    "mac_addresses",
    "hostnames",
    "protocols",
    "first_seen",
    "last_seen",
    "sent_events",
    "received_events",
]

TIMELINE_CSV_HEADER = [
    "timestamp",
    "frame_number",
    "protocol",
    "event_type",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "stream_id",
    "summary",
]

SEVERITIES = {"critical", "high", "medium", "low", "info"}
CONFIDENCES = {"high", "medium", "low"}
INDICATOR_TYPES = {"ip", "domain", "url", "hash", "filename", "user_agent", "sni"}


class SchemaValidationError(ValueError):
    pass


def validate_case_json(data: dict[str, Any]) -> None:
    _require_keys(data, CASE_REQUIRED_FIELDS, "case.json")
    _require_keys(data["capture"], CAPTURE_REQUIRED_FIELDS, "case.capture")
    _require_keys(data["run"], RUN_REQUIRED_FIELDS, "case.run")
    for finding in data["findings"]:
        validate_finding(finding)
    for indicator in data["indicators"]:
        validate_indicator(indicator)


def validate_finding(data: dict[str, Any]) -> None:
    _require_keys(data, FINDING_REQUIRED_FIELDS, "finding")
    if data["severity"] not in SEVERITIES:
        raise SchemaValidationError(f"invalid severity: {data['severity']}")
    if data["confidence"] not in CONFIDENCES:
        raise SchemaValidationError(f"invalid confidence: {data['confidence']}")
    if not isinstance(data["evidence"], list) or not data["evidence"]:
        raise SchemaValidationError("finding evidence must be a non-empty list")
    for evidence in data["evidence"]:
        validate_evidence(evidence)


def validate_indicator(data: dict[str, Any]) -> None:
    _require_keys(data, INDICATOR_REQUIRED_FIELDS, "indicator")
    if data["type"] not in INDICATOR_TYPES:
        raise SchemaValidationError(f"invalid indicator type: {data['type']}")
    if not isinstance(data["evidence"], list):
        raise SchemaValidationError("indicator evidence must be a list")
    for evidence in data["evidence"]:
        validate_evidence(evidence)


def validate_evidence(data: dict[str, Any]) -> None:
    _require_keys(data, EVIDENCE_REQUIRED_FIELDS, "evidence")
    if not isinstance(data["frame_number"], int):
        raise SchemaValidationError("evidence.frame_number must be an integer")
    if not data["reproduction_command"]:
        raise SchemaValidationError("evidence.reproduction_command is required")


def validate_extracted_manifest(data: dict[str, Any]) -> None:
    _require_keys(data, EXTRACTED_MANIFEST_REQUIRED_FIELDS, "extracted manifest")
    if data["schema_version"] != SCHEMA_VERSION:
        raise SchemaValidationError(f"expected extracted manifest schema_version {SCHEMA_VERSION}")
    if not isinstance(data["objects"], list):
        raise SchemaValidationError("extracted manifest objects must be a list")
    for obj in data["objects"]:
        _require_keys(obj, EXTRACTED_OBJECT_REQUIRED_FIELDS, "extracted object")


def _require_keys(data: Any, required: set[str], name: str) -> None:
    if not isinstance(data, dict):
        raise SchemaValidationError(f"{name} must be an object")
    missing = required - set(data)
    if missing:
        raise SchemaValidationError(f"{name} missing required field(s): {', '.join(sorted(missing))}")
