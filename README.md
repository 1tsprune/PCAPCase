# PCAPCase

Network forensics CLI that turns PCAP files into timelines, host inventories,
extracted objects, IOCs, and evidence-backed findings.

License: MIT · Platform: Windows/Linux · Language: Python · Engine: TShark · Status: v1.0 stable tool

## If you are... Start here

| If you are... | Start here |
| --- | --- |
| A SOC analyst triaging a PCAP | `pcapcase analyze sample.pcap --output case` + `report.md` |
| A DFIR analyst validating evidence | [methodology/02-evidence-model.md](methodology/02-evidence-model.md) |
| A detection engineer | [mapping/network-behavior-coverage.md](mapping/network-behavior-coverage.md) |
| A student learning packet forensics | [methodology/00-pcapcase-process.md](methodology/00-pcapcase-process.md) |
| A contributor adding a detector | [templates/detector-spec.md](templates/detector-spec.md) |
| A recruiter / hiring manager | README + methodology docs + sample report |

## What this is

PCAPCase is an evidence-first packet forensics workflow. It uses local TShark to dissect PCAP files, then normalizes the output into timelines, host inventories, IOCs, extracted objects, and findings. It does not upload captures, execute files, or generate unsupported conclusions. Every finding keeps the frame number and reproduction command so another analyst can verify it.

## Quick start

```bash
python -m pip install -e .
pcapcase doctor
pcapcase analyze incident.pcap --output case --html
```

Filtering is available at analysis time:

```bash
pcapcase analyze incident.pcap --host 10.0.0.5 --protocol dns,http \
  --start 2024-01-01T00:00:00Z --end 2024-01-01T01:00:00Z
```

Optional YARA scanning is local-only and opt-in:

```bash
pcapcase analyze incident.pcap --extract-http --yara-rules ./rules/
```

## Methodology

PCAPCase follows `Ingest → Scope → Extract → Correlate → Validate → Report`. See `methodology/` for the evidence model, reporting standard, and investigation techniques.

## What PCAPCase extracts

- Capture metadata and SHA-256
- DNS, HTTP, TLS, ARP, ICMP, and TCP timeline events
- Host inventory
- IOCs: IPs, domains, URLs, SNI, filenames, user agents, and hashes
- HTTP extracted objects with a manifest
- Evidence-backed findings

## Detection library

v1.0 includes core triage, the detection pack for ARP/ICMP/TCP scans, suspicious executable downloads, HTTP upload/possible exfiltration, cleartext credential exposure, optional local YARA scanning of extracted objects, stable output schemas, and a detector plugin interface.

## Example output

```text
case/
├── report.md
├── report.html
├── timeline.csv
├── hosts.csv
├── iocs.json
├── findings.json
├── rerun-manifest.json
└── extracted-files/
    └── manifest.json
```

## Project structure

Implementation lives under `src/pcapcase/`; methodology, mapping, cases, templates, docs, and tests support repeatable analysis.

## TShark dependency

PCAPCase shells out to local `tshark` with subprocess argument arrays and never uses `shell=True`. Install Wireshark/TShark and ensure `tshark` is on `PATH`.

## Roadmap

- v0.1: core triage
- v0.2: detection pack
- v0.3: analyst workflow
- v1.0: stable schemas, STIX export, packaging, Docker support, and plugin interface

## Security and privacy

PCAPCase is offline-only. It never uploads captures or derived data, never executes extracted files, redacts secrets by default, sanitizes carved object filenames, and prevents path traversal.

## Author

PCAPCase contributors.

## License

MIT
