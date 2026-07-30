from datetime import datetime, timezone

from pcapcase.models import CaptureMetadata, CaseResult, RunMetadata
from pcapcase.output.html import render
from pcapcase.report import build_report_data


def test_html_report_escapes_values():
    now = datetime(2024, 1, 1, tzinfo=timezone.utc)
    case = CaseResult(
        CaptureMetadata("<incident>.pcap", "a" * 64, "TShark", 0, now, now, 0),
        [],
        [],
        [],
        [],
        [],
        RunMetadata("0.3.0", now, ["analyze"], "TShark", "a" * 64, "case"),
    )
    html = render(build_report_data(case, {"run_timestamp": "2024-01-01T00:00:00Z", "cli_args": ["analyze"]}))
    assert "&lt;incident&gt;.pcap" in html
    assert "<incident>.pcap" not in html
