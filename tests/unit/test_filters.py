from datetime import datetime, timezone

from pcapcase.filters import filter_events, parse_protocols
from pcapcase.models import NetworkEvent


def event(frame, ts, proto, src, dst):
    return NetworkEvent(datetime.fromisoformat(ts).replace(tzinfo=timezone.utc), proto, src, None, dst, None, proto, proto, frame, None, {})


def test_filter_by_host_time_and_protocol():
    events = [
        event(1, "2024-01-01T00:00:00", "dns", "10.0.0.1", "8.8.8.8"),
        event(2, "2024-01-01T00:10:00", "http", "10.0.0.2", "203.0.113.5"),
        event(3, "2024-01-01T00:20:00", "tcp", "10.0.0.1", "10.0.0.3"),
    ]
    result = filter_events(events, host="10.0.0.1", start=datetime(2024, 1, 1, 0, 5, tzinfo=timezone.utc), protocols={"tcp", "dns"})
    assert [item.frame_number for item in result] == [3]


def test_parse_protocols_rejects_unknown():
    try:
        parse_protocols("dns,ftp")
    except ValueError as exc:
        assert "ftp" in str(exc)
    else:
        raise AssertionError("expected ValueError")
