from pathlib import Path

from pcapcase.extract import object_from_file
from pcapcase.yara_scan import _finding_from_matches


def test_yara_match_becomes_finding_without_secret_or_execution(tmp_path: Path):
    sample = tmp_path / "payload.bin"
    raw_payload = "SECRET_TOKEN_abc123"
    sample.write_text(raw_payload, encoding="utf-8")
    obj = object_from_file(sample, source_frame=10, tcp_stream=4)
    finding = _finding_from_matches(obj, ["SyntheticRule"], "test")
    assert finding.title == "YARA match on extracted object"
    assert finding.evidence[0].frame_number == 10
    assert "SyntheticRule" in finding.description
    assert raw_payload not in finding.description
