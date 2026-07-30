# MITRE ATT&CK Coverage

This file records ATT&CK mappings for detectors that currently exist in `src/pcapcase/detectors/`. Mappings are emitted into `Finding.mitre_attack` when the detector fires; they are not attribution claims.

| PCAPCase behavior | Detector | ATT&CK technique | Tactic | Mapping confidence | Implementation status | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| ARP sweep | `pcapcase.detectors.scan.detect_arp_sweeps` | T1018 Remote System Discovery | Discovery | medium | Implemented | ARP sweeps can support remote system discovery, but benign inventory/monitoring tools can produce similar traffic. |
| ICMP ping sweep | `pcapcase.detectors.scan.detect_icmp_sweeps` | T1018 Remote System Discovery | Discovery | medium | Implemented | ICMP sweeps identify reachable hosts; mapping remains contextual. |
| TCP port scan | `pcapcase.detectors.scan.detect_tcp_port_scans` | T1046 Network Service Discovery | Discovery | high | Implemented | T1046 explicitly covers port and service scanning; detector requires SYN-like attempts across many ports or hosts. |
| HTTP executable/script/archive download | `pcapcase.detectors.download.SuspiciousDownloadDetector` | T1105 Ingress Tool Transfer | Command and Control | medium | Implemented | Packet evidence shows transfer behavior, not final malware execution or attribution. |
| HTTP upload / possible exfiltration | `pcapcase.detectors.exfiltration.detect` | T1041 Exfiltration Over C2 Channel | Exfiltration | medium | Implemented | Upload-like behavior can be benign; analyst validation is required. |
| Cleartext credential observed | `pcapcase.detectors.credentials.detect` | T1552 Unsecured Credentials | Credential Access | medium | Implemented | The detector redacts secrets and reports exposure; whether this is adversary credential access depends on incident context. |

## Not yet implemented

- DNS anomaly detection is not currently shipped as `anomaly.py`, so no ATT&CK mapping is emitted for it.
