# Network Behavior Coverage

| Behavior | Status | Detector | Output | MITRE mapping | Notes |
| --- | --- | --- | --- | --- | --- |
| ARP sweep | Implemented | `pcapcase.detectors.scan.detect_arp_sweeps` | Finding + timeline evidence | T1018 Remote System Discovery, confidence medium | Emits frame-level evidence and reproduction command. |
| ICMP ping sweep | Implemented | `pcapcase.detectors.scan.detect_icmp_sweeps` | Finding + timeline evidence | T1018 Remote System Discovery, confidence medium | Requires many distinct ICMP echo targets in a short window. |
| TCP port scan | Implemented | `pcapcase.detectors.scan.detect_tcp_port_scans` | Finding + timeline evidence | T1046 Network Service Discovery, confidence high | Confirmed to fire on the synthetic `naissur.pcap` fixture; mapping was added after audit found it missing. |
| HTTP executable/script/archive download | Implemented | `pcapcase.detectors.download.SuspiciousDownloadDetector` | Finding + IOC/extracted object context | T1105 Ingress Tool Transfer, confidence medium | Detects suspicious HTTP GET downloads by extension/content type. |
| HTTP upload / possible exfiltration | Implemented | `pcapcase.detectors.exfiltration.detect` | Finding + IOC context | T1041 Exfiltration Over C2 Channel, confidence medium | Upload-like behavior requires analyst validation. |
| Cleartext credential observed | Implemented | `pcapcase.detectors.credentials.detect` | Finding with redacted evidence | T1552 Unsecured Credentials, confidence medium | Secret values are redacted before findings/report output. |
| DNS anomaly | Backlog | none | none | none | No `anomaly.py` detector exists in the current repo. |
| Active Scanning (External) | Backlog | none | none | T1595 | Needs logic to differentiate between internal network discovery (T1018) and external inbound scanning. |
| Beaconing (Web Protocols) | Backlog | none | none | T1071.001 | Needs timing analysis of repeated, uniform HTTP connections to a single domain. |
| DNS Tunneling | Backlog | none | none | T1071.004 | Needs anomaly logic for DNS tunneling (payload entropy, extreme subdomain lengths, high DNS query volume). |
| Non-Standard Port | Backlog | none | none | T1571 | Needs deep packet inspection to detect protocol mismatches (e.g., HTTP traffic occurring on port 4444 instead of 80/443). |
| Encrypted Channel Anomalies | Backlog | none | none | T1573 | Needs TLS handshake parsing to identify anomalies like SNI mismatches, self-signed certificates, or JA3 hash blocklisting. |
| Alternative Protocol Exfiltration | Backlog | none | none | T1048 | Needs volume/entropy analysis over protocols not typically used for data transfer (DNS TXT records, ICMP payloads, raw TCP streams). |
| Brute Force | Backlog | none | none | T1110 | Needs stateful tracking of repeated authentication failures over time against a single service (e.g., multiple HTTP 401s followed by a 200). |
| Adversary-in-the-Middle (ARP Spoofing) | Backlog | none | none | T1557 | Needs tracking state to identify conflicting MAC-to-IP claims for ARP spoofing, rather than just basic ARP sweeps. |
