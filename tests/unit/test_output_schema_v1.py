from datetime import datetime, timezone

from pcapcase.models import (
    CaptureMetadata,
    CaseResult,
    Evidence,
    Finding,
    Host,
    Indicator,
    NetworkEvent,
    RunMetadata,
)
from pcapcase.schema import (
    HOSTS_CSV_HEADER,
    SCHEMA_VERSION,
    TIMELINE_CSV_HEADER,
    validate_case_json,
    validate_extracted_manifest,
    validate_finding,
    validate_indicator,
)


def test_case_json_matches_schema_v1_contract():
    now = datetime(2024, 1, 1, tzinfo=timezone.utc)
    evidence = Evidence(1, now, "http", 7, "http.request.full_uri", "http://example.test/file.bin", "tshark -r sample.pcap -Y frame.number==1")
    finding = Finding(
        id="finding-1",
        title="Basic HTTP download observed",
        description="A basic HTTP download was observed.",
        severity="info",
        confidence="medium",
        category="http-download",
        first_seen=now,
        last_seen=now,
        source_hosts=["10.0.0.5"],
        destination_hosts=["203.0.113.10"],
        evidence=[evidence],
        recommendations=["Validate the download context."],
    )
    indicator = Indicator("url", "http://example.test/file.bin", now, now, "http.request.full_uri", [evidence])
    event = NetworkEvent(now, "http_request", "10.0.0.5", 51515, "203.0.113.10", 80, "http", "GET http://example.test/file.bin", 1, 7, {})
    case = CaseResult(
        capture=CaptureMetadata("sample.pcap", "a" * 64, "TShark 4.2.0", 1, now, now, 0.0),
        hosts=[Host("10.0.0.5", protocols=["http"], first_seen=now, last_seen=now, sent_events=1)],
        events=[event],
        indicators=[indicator],
        extracted_objects=[],
        findings=[finding],
        run=RunMetadata("1.0.0", now, ["analyze", "sample.pcap"], "TShark 4.2.0", "a" * 64, "case"),
    )
    data = case.to_dict()
    validate_case_json(data)
    validate_finding(data["findings"][0])
    validate_indicator(data["indicators"][0])


def test_csv_headers_are_frozen():
    assert HOSTS_CSV_HEADER == ["ip", "mac_addresses", "hostnames", "protocols", "first_seen", "last_seen", "sent_events", "received_events"]
    assert TIMELINE_CSV_HEADER == ["timestamp", "frame_number", "protocol", "event_type", "src_ip", "src_port", "dst_ip", "dst_port", "stream_id", "summary"]


def test_extracted_manifest_schema_v1_contract():
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "objects": [
            {
                "sha256": "b" * 64,
                "original_filename": "payload.bin",
                "sanitized_filename": "payload.bin",
                "size": 3,
                "source_frame": 12,
                "tcp_stream": 4,
                "extraction_timestamp": "2024-01-01T00:00:00Z",
                "path": "case/extracted-files/payload.bin",
                "yara_matches": [],
            }
        ],
    }
    validate_extracted_manifest(manifest)
