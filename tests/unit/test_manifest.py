from datetime import datetime, timezone

from pcapcase.manifest import build_rerun_manifest


def test_rerun_manifest_records_audit_inputs():
    manifest = build_rerun_manifest(
        input_path="incident.pcap",
        input_sha256="a" * 64,
        tshark_version="TShark 4.2.0",
        cli_args=["analyze", "incident.pcap", "--host", "10.0.0.1"],
        output_directory="case",
        filters={"host": "10.0.0.1"},
        optional_features={"html": True},
        run_timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
    )
    data = manifest.to_dict()
    assert data["input_sha256"] == "a" * 64
    assert data["run_timestamp"] == "2024-01-01T00:00:00Z"
    assert data["filters"]["host"] == "10.0.0.1"
    assert data["optional_features"]["html"] is True
