# PCAPCase Project Plan

## Summary

PCAPCase is an offline-first network forensics CLI that turns packet captures into investigation timelines, host inventories, extracted objects, indicators of compromise, and evidence-backed findings.

```bash
pcapcase analyze incident.pcap --output ./case
```

Expected output:

```text
case/
├── report.md
├── timeline.csv
├── hosts.csv
├── iocs.json
├── findings.json
├── extracted-files/
└── evidence/
```

## Positioning

GitHub description:

> Network forensics CLI that turns PCAP files into investigation timelines, host inventories, extracted objects, IOCs, and evidence-backed findings.

Tagline:

> From packet capture to defensible findings.

PCAPCase should reduce repetitive first-pass Wireshark work without hiding the evidence from the analyst. Every automated conclusion must reference the relevant frame number, timestamp, stream ID, and a reproducible TShark command.

### Product principles

- Evidence first
- Offline by default
- Reproducible findings
- Useful for SOC and DFIR analysts
- No capture data sent to external services
- No unsupported conclusions
- Useful structured output as well as a readable report

PCAPCase must not become a thin TShark wrapper that only produces a long report. Its value comes from correlation, evidence references, reusable output, and practical detections.

## Target users

- SOC analysts performing initial packet triage
- DFIR analysts reconstructing network activity
- Security engineers validating incidents
- Pentesters reviewing captured traffic
- Students learning evidence-based network forensics

## MVP v0.1

### 1. Capture summary

Collect:

- File name and size
- SHA-256 hash
- Capture start and end time
- Capture duration
- Frame count
- Protocol distribution
- Capture interface metadata when available
- Timezone metadata when available
- Warnings for malformed or truncated packets

### 2. Host inventory

Identify and correlate:

- IPv4 and IPv6 addresses
- MAC addresses
- Hostnames from DNS, DHCP, NBNS, mDNS, and TLS SNI
- First-seen and last-seen timestamps
- Bytes sent and received
- Internal or external classification
- Protocols and ports used

Output: `hosts.csv` and equivalent structured JSON data.

### 3. Investigation timeline

Create one normalized event per row:

```text
timestamp,event_type,src_ip,src_port,dst_ip,dst_port,protocol,summary,frame,stream
```

Initial event types:

- DNS query and response
- HTTP request and response
- TLS connection and SNI
- TCP connection
- ICMP activity
- ARP activity
- File download
- HTTP POST or upload
- Authentication-related traffic when visible

Output: `timeline.csv` and structured JSON data.

### 4. Initial detections

The first detection set should cover:

- Internal ping sweep
- ARP sweep
- Port scanning
- Suspicious executable download
- HTTP upload or possible exfiltration
- Unusual User-Agent
- Cleartext credentials
- Basic DNS anomalies
- Connections to rare external IP addresses

Every finding must include severity, confidence, and direct evidence.

Example:

```yaml
title: Suspicious executable download
severity: high
confidence: high
timestamp: 2024-11-04T13:06:03Z
source: 172.23.4.115
destination: 172.23.4.107:8443
frame: 7485
tcp_stream: 57
evidence: GET /syswor64.exe
```

### 5. IOC extraction

Extract:

- IPv4 and IPv6 addresses
- Domains
- URLs
- Downloaded filenames
- SHA-256 hashes of carved files
- User-Agent strings
- TLS SNI values

Initial outputs:

- `iocs.json`
- `iocs.csv`
- Plain-text list suitable for SIEM use

STIX 2.1 export is not required for the MVP.

### 6. HTTP object extraction

- Export HTTP objects safely
- Calculate MD5, SHA-1, and SHA-256
- Record source frame and TCP stream
- Sanitize extracted filenames
- Warn when an object appears executable
- Never execute extracted files

### 7. Reports

Generate `report.md` containing:

1. Executive summary
2. Capture details
3. Host inventory
4. Findings grouped by severity
5. Investigation timeline
6. Extracted files
7. IOC list
8. Reproduction commands

The report must distinguish observed evidence from analyst interpretation.

## CLI design

```bash
# Full analysis
pcapcase analyze incident.pcap

# Select output directory
pcapcase analyze incident.pcap --output cases/incident-001

# Analyze without carving files
pcapcase analyze incident.pcap --no-extract

# Generate a timeline only
pcapcase timeline incident.pcap --format csv

# List hosts
pcapcase hosts incident.pcap

# Export IOCs
pcapcase iocs incident.pcap --format json

# Validate the local environment
pcapcase doctor
```

Potential common options:

```text
--start <timestamp>
--end <timestamp>
--host <ip-or-hostname>
--protocol <name>
--format <json|csv|markdown>
--verbose
--quiet
```

## Technical direction

### Language

Use Python for the initial release. It fits security CLI workflows, structured data processing, reporting, testing, and packaging.

### Analysis engine

Use the local TShark executable for packet dissection. Python should handle:

- Process execution
- Output parsing
- Event normalization
- Host correlation
- Detection logic
- Evidence tracking
- IOC extraction
- Report generation

Do not build a custom binary PCAP parser in the first version. That would increase scope without improving the core analyst workflow.

### Proposed structure

```text
pcapcase/
├── pyproject.toml
├── README.md
├── LICENSE
├── src/pcapcase/
│   ├── __init__.py
│   ├── cli.py
│   ├── models.py
│   ├── runner.py
│   ├── capture.py
│   ├── timeline.py
│   ├── hosts.py
│   ├── iocs.py
│   ├── extract.py
│   ├── report.py
│   ├── parsers/
│   │   ├── __init__.py
│   │   ├── dns.py
│   │   ├── http.py
│   │   ├── tls.py
│   │   ├── arp.py
│   │   └── icmp.py
│   └── detectors/
│       ├── __init__.py
│       ├── scan.py
│       ├── download.py
│       ├── exfiltration.py
│       └── credentials.py
├── tests/
│   ├── fixtures/
│   ├── unit/
│   └── integration/
└── examples/
    └── sample-report/
```

### Dependency strategy

Keep runtime dependencies small. Potential choices should be evaluated before implementation:

- Typer or Click for CLI handling, or `argparse` for zero dependency
- Pydantic or dataclasses for models
- Jinja2 only if report templates need it
- Rich only if terminal presentation materially improves the workflow

TShark is an external system dependency and must be documented clearly.

## Environment validation

`pcapcase doctor` should verify:

- TShark exists in `PATH` or the configured path
- TShark version is supported
- Required dissectors and fields are available
- The input file is readable
- The output directory is writable
- The current platform is supported

The command should return a non-zero exit code when a required capability is missing.

## Core data model

Suggested entities:

- `CaptureMetadata`
- `Host`
- `NetworkEvent`
- `Indicator`
- `ExtractedObject`
- `Finding`
- `Evidence`
- `CaseResult`

### Evidence model

Evidence references are a defining feature of PCAPCase.

```python
@dataclass
class Evidence:
    frame_number: int
    timestamp: datetime
    protocol: str
    tcp_stream: int | None
    field: str
    value: str
    reproduction_command: str
```

A finding should contain one or more evidence records. Reports and JSON output should expose them rather than presenting conclusions without packet references.

### Finding model

```python
@dataclass
class Finding:
    id: str
    title: str
    description: str
    severity: str
    confidence: str
    category: str
    first_seen: datetime
    last_seen: datetime
    source_hosts: list[str]
    destination_hosts: list[str]
    evidence: list[Evidence]
    recommendations: list[str]
```

Severity and confidence must be separate. A potentially severe behavior with weak evidence should not be presented as confirmed compromise.

## Detection approach

Start with deterministic rules rather than machine learning or LLM-generated conclusions.

Examples:

### Ping sweep

- One source sends ICMP echo requests to multiple internal destinations
- Evaluate destination count within a configurable time window
- Ignore expected monitoring systems through an allowlist

### ARP sweep

- One source requests many unique internal addresses in a short period
- Record each request as evidence

### Port scan

- One source contacts multiple ports on one destination or one port across many destinations
- Use configurable thresholds
- Distinguish completed connections from SYN-only attempts when possible

### Executable download

- HTTP response or exported object indicates PE, ELF, script, archive, or executable content
- Record request URI, response metadata, object hash, frame, and stream

### Possible exfiltration

- HTTP POST or other outbound transfer with a body
- Highlight unusual destination, size, content type, or encoded system information
- Use "possible" language unless evidence confirms sensitive data transfer

### Cleartext credentials

- Detect credentials in supported cleartext protocols and HTTP fields
- Redact secrets in terminal and reports by default
- Preserve enough evidence for analysts to locate the packet

## Security and privacy requirements

- Never upload packet captures automatically
- Never execute extracted content
- Sanitize filenames and prevent path traversal
- Apply resource limits to object extraction
- Redact passwords, tokens, cookies, and authorization headers by default
- Allow explicit unredacted output only with a clear warning
- Avoid shell command construction from untrusted values
- Use subprocess argument arrays instead of `shell=True`
- Record the PCAP hash for case integrity
- Clearly label generated reports as automated triage, not final incident conclusions

## Testing strategy

### Unit tests

- TShark output parsing
- Timestamp normalization
- Host correlation
- IOC normalization and deduplication
- Detection thresholds
- Filename sanitization
- Secret redaction
- Report rendering

### Integration tests

Use synthetic PCAP fixtures for:

- DNS and TLS activity
- HTTP download
- HTTP upload
- Ping sweep
- ARP sweep
- Port scan
- Cleartext credential handling
- IPv6 traffic
- Malformed or truncated packets

Tests should not depend on confidential captures or technical-assessment material.

### Cross-platform target

The MVP must work on:

- Windows with Wireshark/TShark installed
- Linux with TShark installed

macOS support can be best effort until CI coverage exists.

## Naissur as a validation case

The Naissur investigation is useful for privately validating:

- Malware download detection
- HTTP object carving
- Internal reconnaissance detection
- HTTP POST exfiltration detection
- Suspicious User-Agent extraction
- Hostname and username leakage
- Timeline reconstruction

Do not publish the original technical-test PCAP unless redistribution rights are confirmed. Safe alternatives:

- Generate synthetic PCAP fixtures
- Use sanitized output examples
- Recreate equivalent traffic in a controlled lab
- Mention the workflow inspiration without bundling confidential artefacts

## Roadmap

### v0.1: Core triage

- Package and CLI setup
- `doctor` command
- TShark runner
- Capture summary
- DNS, HTTP, TLS, ARP, and ICMP timeline
- Host inventory
- IOC extraction
- Markdown report
- JSON and CSV outputs
- Unit and integration tests

### v0.2: Detection

- Ping sweep detection
- ARP sweep detection
- Port scan detection
- Executable download detection
- HTTP upload and possible exfiltration detection
- Cleartext credential detection
- Severity and confidence scoring
- Evidence references for every finding

### v0.3: Analyst workflow

- HTML report
- Filtering by host, time, and protocol
- Case metadata and analyst notes
- Re-run reproducibility manifest
- Optional YARA scanning for extracted files
- Improved redaction controls

### v1.0: Stable release

- Stable JSON schema
- Plugin interface
- STIX 2.1 export
- User-defined network detections
- Docker image
- Release binaries where practical
- GitHub Actions CI and release automation
- Complete documentation and examples

## Out of scope for the MVP

Do not add these until the core workflow is reliable:

- Web dashboard
- Live packet capture
- Machine learning
- LLM-generated conclusions
- External threat-intelligence APIs
- Automatic malware execution
- Elasticsearch or another database
- A custom binary PCAP parser
- Support for every network protocol
- Multi-user case management

## Definition of done for v0.1

Version 0.1 is complete when one command can:

1. Validate a PCAP or PCAPNG file.
2. Calculate its hash and capture metadata.
3. Identify and summarize the main hosts.
4. Build a DNS, HTTP, TLS, ARP, ICMP, and TCP timeline.
5. Extract and deduplicate IOCs.
6. Identify HTTP downloads and uploads.
7. Generate `report.md`, `timeline.csv`, `hosts.csv`, `iocs.json`, and `findings.json`.
8. Include frame numbers and reproduction commands for findings.
9. Pass tests using synthetic packet captures.
10. Run on Windows and Linux with TShark installed.

## Suggested implementation order

1. Create the standalone repository and Python package.
2. Implement configuration and the `doctor` command.
3. Implement the safe TShark runner.
4. Define capture, event, host, IOC, finding, and evidence models.
5. Implement capture summary extraction.
6. Implement normalized protocol parsers and timeline generation.
7. Implement host correlation.
8. Implement IOC extraction and deduplication.
9. Implement HTTP object extraction.
10. Add download and upload detectors.
11. Implement Markdown, JSON, and CSV output.
12. Create synthetic PCAP fixtures and CI.
13. Publish a sanitized sample report.
14. Tag the first `v0.1.0` release.

## Repository quality checklist

Before featuring PCAPCase in the portfolio, the repository should include:

- Clear README with a short demo
- Installation instructions for Windows and Linux
- TShark dependency instructions
- Architecture overview
- Sample sanitized report
- Screenshots or terminal recording
- Tests and CI badge
- License
- Security and privacy notes
- Known limitations
- Changelog and tagged release
- Issue templates for bugs and protocol support

## Initial handoff prompt

Use this prompt when moving the plan to another coding workflow:

> Implement PCAPCase v0.1 from `007-pcapcase-project-plan.md` as a standalone Python project. Start with project scaffolding, data models, a safe TShark runner, and the `doctor` command. Keep dependencies minimal, support Windows and Linux, use synthetic test fixtures only, and do not implement dashboard, machine learning, external APIs, or LLM analysis. Every generated finding must retain frame-level evidence and a reproducible TShark command. Run tests and document any deviations from the plan.
