from __future__ import annotations

from pathlib import Path

from .models import NetworkEvent
from .parsers import arp, dns, http, icmp, tcp, tls
from .redaction import Redactor
from .runner import TSharkRunner


def build_timeline(pcap_path: str | Path, runner: TSharkRunner, redactor: Redactor) -> list[NetworkEvent]:
    events: list[NetworkEvent] = []
    parsers = [
        lambda: dns.parse(pcap_path, runner),
        lambda: http.parse(pcap_path, runner, redactor),
        lambda: tls.parse(pcap_path, runner),
        lambda: arp.parse(pcap_path, runner),
        lambda: icmp.parse(pcap_path, runner),
        lambda: tcp.parse(pcap_path, runner),
    ]
    for parser in parsers:
        try:
            events.extend(parser())
        except Exception:
            continue
    return sort_events(events)


def sort_events(events: list[NetworkEvent]) -> list[NetworkEvent]:
    return sorted(events, key=lambda event: (event.timestamp, event.frame_number, event.protocol, event.event_type, event.summary))
