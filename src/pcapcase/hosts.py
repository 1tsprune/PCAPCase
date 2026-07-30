from __future__ import annotations

from collections import defaultdict

from .models import Host, NetworkEvent


def build_hosts(events: list[NetworkEvent]) -> list[Host]:
    data: dict[str, dict[str, object]] = defaultdict(lambda: {
        "protocols": set(),
        "first": None,
        "last": None,
        "sent": 0,
        "received": 0,
        "macs": set(),
        "hostnames": set(),
    })
    for event in events:
        for role, ip in (("sent", event.src_ip), ("received", event.dst_ip)):
            if not ip:
                continue
            item = data[ip]
            item["protocols"].add(event.protocol)  # type: ignore[union-attr]
            item[role] = int(item[role]) + 1  # type: ignore[arg-type]
            first = item["first"]
            last = item["last"]
            item["first"] = event.timestamp if first is None or event.timestamp < first else first
            item["last"] = event.timestamp if last is None or event.timestamp > last else last
            for key in ("arp.src.hw_mac", "arp.dst.hw_mac"):
                value = event.raw.get(key)
                if value:
                    item["macs"].add(value)  # type: ignore[union-attr]
            for key in ("dns.qry.name", "http.host", "tls.handshake.extensions_server_name"):
                value = event.raw.get(key)
                if value:
                    item["hostnames"].add(value)  # type: ignore[union-attr]
    hosts: list[Host] = []
    for ip, item in sorted(data.items()):
        hosts.append(
            Host(
                ip=ip,
                mac_addresses=sorted(item["macs"]),  # type: ignore[arg-type]
                hostnames=sorted(item["hostnames"]),  # type: ignore[arg-type]
                protocols=sorted(item["protocols"]),  # type: ignore[arg-type]
                first_seen=item["first"],  # type: ignore[arg-type]
                last_seen=item["last"],  # type: ignore[arg-type]
                sent_events=int(item["sent"]),
                received_events=int(item["received"]),
            )
        )
    return hosts
