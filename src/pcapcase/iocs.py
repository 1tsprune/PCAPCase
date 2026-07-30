from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from .models import Evidence, Indicator, NetworkEvent

_DOMAIN = re.compile(r"\b(?=.{1,253}\b)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\b")
_HASH = re.compile(r"\b[A-Fa-f0-9]{32}\b|\b[A-Fa-f0-9]{40}\b|\b[A-Fa-f0-9]{64}\b")


def extract_iocs(events: list[NetworkEvent]) -> list[Indicator]:
    grouped: dict[tuple[str, str], dict[str, Any]] = defaultdict(lambda: {"first": None, "last": None, "evidence": [], "source": set()})
    for event in events:
        candidates: list[tuple[str, str, str]] = []
        for ip in (event.src_ip, event.dst_ip):
            if ip:
                candidates.append(("ip", ip, "network_event"))
        for key in ("dns.qry.name", "dns.resp.name", "http.host"):
            value = event.raw.get(key)
            if value:
                candidates.append(("domain", value, key))
        uri = event.raw.get("http.request.full_uri")
        if uri:
            candidates.append(("url", uri, "http.request.full_uri"))
            filename = uri.rstrip("/").split("/")[-1].split("?")[0]
            if filename and "." in filename:
                candidates.append(("filename", filename, "http.request.full_uri"))
        ua = event.raw.get("http.user_agent")
        if ua:
            candidates.append(("user_agent", ua, "http.user_agent"))
        sni = event.raw.get("tls.handshake.extensions_server_name")
        if sni:
            candidates.append(("sni", sni, "tls.handshake.extensions_server_name"))
        for text in (event.summary, *event.raw.values()):
            for match in _HASH.findall(text or ""):
                candidates.append(("hash", match.lower(), "raw"))
            for match in _DOMAIN.findall(text or ""):
                candidates.append(("domain", match.lower(), "raw"))
        for typ, value, source in candidates:
            if not value:
                continue
            key = (typ, value)
            item = grouped[key]
            item["first"] = event.timestamp if item["first"] is None or event.timestamp < item["first"] else item["first"]
            item["last"] = event.timestamp if item["last"] is None or event.timestamp > item["last"] else item["last"]
            item["source"].add(source)
            item["evidence"].append(_evidence(event, source, value))
    indicators: list[Indicator] = []
    for (typ, value), item in sorted(grouped.items()):
        indicators.append(Indicator(typ, value, item["first"], item["last"], ",".join(sorted(item["source"])), item["evidence"][:5]))
    return indicators


def _evidence(event: NetworkEvent, field: str, value: str) -> Evidence:
    return Evidence(event.frame_number, event.timestamp, event.protocol, event.stream_id, field, value, event.raw.get("_tshark_command", f'tshark -r <pcap> -Y "frame.number=={event.frame_number}"'))
