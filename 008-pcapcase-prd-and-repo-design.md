# PCAPCase PRD and Repository Design

## Reference style

This plan borrows the strongest structural ideas from `rizko-d/threat-hunting-sentinel-defender`:

- A README that explains the project as a process, not just a tool.
- A clear "If you are... start here" table.
- A methodology folder that documents how the work should be done.
- A mapping folder for coverage, gaps, and machine-readable metadata.
- Templates for repeatable contributions.
- A main content library organized by analyst workflow.
- A roadmap that shows what is done, what is next, and where the project is going.

PCAPCase should use the same discipline, but for packet forensics and incident reconstruction.

---

# 1. Product Requirements Document

## Product name

**PCAPCase**

## Tagline

**From packet capture to defensible findings.**

## One-line description

PCAPCase is an offline network forensics CLI that turns PCAP files into timelines, host inventories, extracted objects, IOCs, and evidence-backed findings.

## GitHub description

> Network forensics CLI that turns PCAP files into investigation timelines, host inventories, extracted objects, IOCs, and evidence-backed findings.

## Problem

Network forensics often starts with a blank Wireshark window and a messy capture. Analysts repeat the same first-pass triage steps:

- Check capture metadata.
- Identify active hosts.
- Find DNS, HTTP, TLS, ARP, ICMP, and TCP activity.
- Reconstruct timelines.
- Carve HTTP objects.
- Extract IOCs.
- Look for scan, download, upload, credential leakage, and exfiltration clues.
- Document frame numbers and evidence.

The work is not hard because one command is difficult. It is hard because the process is repetitive, easy to miss under time pressure, and often poorly documented.

## Product goal

PCAPCase should make the first 30 to 60 minutes of packet triage repeatable and defensible.

The tool should not replace analyst judgment. It should produce structured evidence that helps an analyst answer:

1. What happened?
2. Which hosts were involved?
3. When did it happen?
4. What data moved?
5. What indicators can be extracted?
6. Which frames prove the finding?
7. How can another analyst reproduce the result?

## Non-goals

PCAPCase is not:

- A full Wireshark replacement.
- A malware sandbox.
- A SIEM.
- A live packet capture tool.
- A threat intelligence platform.
- An LLM incident report generator.
- A web dashboard for v0.1.
- A tool that uploads captures to third-party services.

## Primary users

| User | Need | PCAPCase value |
| --- | --- | --- |
| SOC analyst | Quick first-pass triage | Timeline, hosts, IOCs, findings |
| DFIR analyst | Evidence-backed reconstruction | Frame references and reproduction commands |
| Detection engineer | Turn packet evidence into detections | IOC and behavior extraction |
| Pentester | Review captured traffic and produce proof | Findings with evidence and report output |
| Student | Learn structured packet investigation | Methodology, examples, and repeatable cases |
| Recruiter / hiring manager | Understand security engineering depth | Tool + methodology + documentation |

## Core product promise

PCAPCase takes this:

```text
incident.pcap
```

And produces this:

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

Every finding should answer:

```text
What happened?
Why does it matter?
Where is the packet evidence?
How can I reproduce this with TShark?
```

---

# 2. Analyst workflow

## Six-phase PCAPCase methodology

PCAPCase should document and implement a repeatable investigation loop:

```text
Ingest → Scope → Extract → Correlate → Validate → Report
```

### 1. Ingest

Validate the capture and environment.

- Is the file readable?
- Is it PCAP or PCAPNG?
- Is TShark available?
- What is the file hash?
- What time range does the capture cover?
- Is the capture truncated or malformed?

### 2. Scope

Understand the capture boundary.

- Which hosts appear?
- Which host seems like the victim?
- Which hosts are internal or external?
- Which protocols dominate?
- What time window matters?

### 3. Extract

Pull raw observable events.

- DNS queries
- HTTP requests and responses
- TLS SNI
- ARP activity
- ICMP activity
- TCP connection metadata
- HTTP objects
- User-Agent strings
- URLs, domains, IPs, and filenames

### 4. Correlate

Connect events into behavior.

- Download followed by execution-like traffic.
- Internal recon followed by upload.
- Rare external destination after host discovery.
- Suspicious User-Agent linked to an HTTP POST.
- Hostname/user leakage in uploaded data.

### 5. Validate

Attach evidence and reduce false claims.

- Frame number
- TCP stream
- Timestamp
- Extracted field
- Reproduction command
- Confidence level
- Reason for severity

### 6. Report

Produce analyst-ready outputs.

- Executive summary
- Findings by severity
- Timeline
- Hosts
- IOCs
- Extracted objects
- Reproduction commands
- Known limitations

## Methodology docs to ship

PCAPCase should include these methodology files:

```text
methodology/
├── 00-pcapcase-process.md
├── 01-scope-and-triage.md
├── 02-evidence-model.md
├── 03-network-forensics-techniques.md
├── 04-findings-and-confidence.md
└── 05-reporting-standard.md
```

### `00-pcapcase-process.md`

Covers the full investigation loop:

- Ingest
- Scope
- Extract
- Correlate
- Validate
- Report

### `01-scope-and-triage.md`

Covers how to identify:

- Victim host candidates
- Internal and external networks
- Time windows
- Main protocol families
- Noisy but low-value traffic

### `02-evidence-model.md`

Defines evidence standards:

- Frame-level reference
- TCP stream reference
- Timestamp normalization
- Reproduction commands
- Redaction rules
- Difference between observed evidence and interpretation

### `03-network-forensics-techniques.md`

Documents reusable techniques:

- DNS pivoting
- HTTP object carving
- TLS SNI review
- ARP/ICMP recon detection
- TCP stream following
- IOC extraction
- Upload/exfil review
- Cleartext credential search

### `04-findings-and-confidence.md`

Defines:

- Severity levels
- Confidence levels
- False-positive handling
- When to say "possible" versus "confirmed"
- How a packet clue becomes a finding

### `05-reporting-standard.md`

Defines report quality:

- Executive summary rules
- Evidence table format
- IOC table format
- Timeline format
- Reproduction command format
- Redaction expectations

---

# 3. Repository design

## Proposed structure

```text
pcapcase/
├── README.md
├── ATTACK_NETWORK_MATRIX.md
├── CHANGELOG.md
├── LICENSE
├── SECURITY.md
├── pyproject.toml
├── methodology/
│   ├── 00-pcapcase-process.md
│   ├── 01-scope-and-triage.md
│   ├── 02-evidence-model.md
│   ├── 03-network-forensics-techniques.md
│   ├── 04-findings-and-confidence.md
│   └── 05-reporting-standard.md
├── docs/
│   ├── installation.md
│   ├── tshark-fields.md
│   ├── output-schema.md
│   ├── examples.md
│   ├── limitations.md
│   └── index.md
├── cases/
│   ├── malware-download/
│   ├── internal-recon/
│   ├── http-exfiltration/
│   ├── dns-anomaly/
│   └── credential-leakage/
├── mapping/
│   ├── network-behavior-coverage.md
│   ├── mitre-attack-coverage.md
│   ├── detection-taxonomy.yaml
│   └── tshark-field-map.yaml
├── templates/
│   ├── case-card.md
│   ├── finding.md
│   ├── detector-spec.md
│   └── report.md
├── src/pcapcase/
│   ├── __init__.py
│   ├── cli.py
│   ├── config.py
│   ├── models.py
│   ├── runner.py
│   ├── capture.py
│   ├── timeline.py
│   ├── hosts.py
│   ├── iocs.py
│   ├── extract.py
│   ├── report.py
│   ├── output/
│   │   ├── json.py
│   │   ├── csv.py
│   │   └── markdown.py
│   ├── parsers/
│   │   ├── dns.py
│   │   ├── http.py
│   │   ├── tls.py
│   │   ├── arp.py
│   │   ├── icmp.py
│   │   └── tcp.py
│   └── detectors/
│       ├── scan.py
│       ├── download.py
│       ├── exfiltration.py
│       ├── credentials.py
│       └── anomaly.py
├── tests/
│   ├── fixtures/
│   ├── unit/
│   └── integration/
├── examples/
│   ├── sample-case/
│   └── sample-report/
└── .github/
    └── workflows/
        ├── test.yml
        └── lint.yml
```

## Why this structure works

| Folder | Purpose |
| --- | --- |
| `methodology/` | Shows the investigation process and professional reasoning. |
| `cases/` | Provides reusable case cards for common network-forensics scenarios. |
| `mapping/` | Shows coverage, gaps, and machine-readable mappings. |
| `templates/` | Makes contributions consistent. |
| `docs/` | Documents installation, schema, fields, and limitations. |
| `src/pcapcase/` | Actual CLI implementation. |
| `examples/` | Public sanitized outputs for portfolio/demo use. |
| `.github/workflows/` | CI credibility. |

This makes the repository look like a serious security engineering project, not a random script.

---

# 4. README design

The README should be written as a landing page.

## README outline

```text
# PCAPCase

Network forensics CLI that turns PCAP files into timelines, host inventories,
extracted objects, IOCs, and evidence-backed findings.

License · Platform · Language · Engine · Status

## If you are... Start here
## What this is
## Quick start
## Methodology
## What PCAPCase extracts
## Detection library
## Example output
## Project structure
## TShark dependency
## Roadmap
## Security and privacy
## Author
## License
```

## Start-here table

```md
## If you are... Start here

| If you are... | Start here |
| --- | --- |
| A SOC analyst triaging a PCAP | `pcapcase analyze sample.pcap` + `report.md` |
| A DFIR analyst validating evidence | `methodology/02-evidence-model.md` |
| A detection engineer | `mapping/network-behavior-coverage.md` |
| A student learning packet forensics | `methodology/00-pcapcase-process.md` |
| A contributor adding a detector | `templates/detector-spec.md` |
| A recruiter / hiring manager | README + methodology docs + sample report |
```

## What this is

Suggested README wording:

> PCAPCase is an evidence-first packet forensics workflow. It uses local TShark to dissect PCAP files, then normalizes the output into timelines, host inventories, IOCs, extracted objects, and findings. It does not upload captures, execute files, or generate unsupported conclusions. Every finding keeps the frame number and reproduction command so another analyst can verify it.

---

# 5. Case Card system

The reference repo uses Hunt Cards. PCAPCase should use **Case Cards**.

A Case Card documents a type of packet investigation and maps it to PCAPCase outputs.

## Case library structure

```text
cases/
├── malware-download/
│   ├── suspicious-executable-download.md
│   └── script-download-over-http.md
├── internal-recon/
│   ├── arp-sweep.md
│   ├── icmp-ping-sweep.md
│   └── tcp-port-scan.md
├── http-exfiltration/
│   ├── powershell-http-post.md
│   └── browser-form-upload.md
├── dns-anomaly/
│   ├── dns-tunneling-suspect.md
│   └── suspicious-nxdomain-burst.md
└── credential-leakage/
    ├── basic-auth.md
    └── cleartext-form-password.md
```

## Case Card template

```md
# Suspicious executable download

## Objective

Identify executable or script downloads over HTTP and preserve frame-level evidence.

## Why it matters

Malware delivery often starts with a simple HTTP GET. Even when the binary is deleted from disk, the packet capture may preserve the transfer metadata or the object itself.

## Observable behavior

- HTTP request for executable-like extension
- Binary response body
- PE, ELF, script, archive, or macro document content
- Suspicious filename or path
- Rare source or destination host

## PCAPCase detector

`detectors/download.py`

## TShark fields

- `frame.number`
- `frame.time_utc`
- `ip.src`
- `ip.dst`
- `tcp.stream`
- `http.request.method`
- `http.request.full_uri`
- `http.response.code`
- `http.content_type`
- `http.user_agent`

## Example command

```bash
tshark -r incident.pcap -Y "http.request || http.response" \
  -T fields -e frame.number -e frame.time_utc -e ip.src -e ip.dst \
  -e tcp.stream -e http.request.method -e http.request.full_uri \
  -e http.response.code -e http.content_type -e http.user_agent
```

## Finding criteria

| Severity | Criteria |
| --- | --- |
| High | Executable object downloaded from suspicious or rare host |
| Medium | Script/archive downloaded with weak context |
| Low | Benign-looking download but relevant to investigation scope |

## Evidence required

- Request frame
- Response frame when available
- TCP stream
- File name or URI
- Hash if object was carved
- Reproduction command

## False positives

- Software updates
- Internal package repositories
- Browser downloads by user action
- Known admin tooling

## Output fields

- `finding.title`
- `finding.severity`
- `finding.confidence`
- `evidence.frame_number`
- `evidence.tcp_stream`
- `extracted_object.sha256`
- `indicator.url`
```

---

# 6. Mapping design

Mapping is what makes the repo look mature. It shows what the tool covers and where gaps remain.

## `mapping/network-behavior-coverage.md`

A human-readable coverage table.

```md
# Network Behavior Coverage

| Behavior | Status | Detector | Output | Notes |
| --- | --- | --- | --- | --- |
| HTTP executable download | Planned | `download.py` | Finding + object hash | v0.2 |
| HTTP upload / possible exfil | Planned | `exfiltration.py` | Finding + IOC | v0.2 |
| ARP sweep | Planned | `scan.py` | Finding + timeline | v0.2 |
| ICMP sweep | Planned | `scan.py` | Finding + timeline | v0.2 |
| TCP port scan | Planned | `scan.py` | Finding + timeline | v0.2 |
| DNS anomaly | Backlog | `anomaly.py` | Finding | v0.3 |
| Cleartext credentials | Planned | `credentials.py` | Finding with redaction | v0.2 |
```

## `mapping/mitre-attack-coverage.md`

Map packet behaviors to ATT&CK where appropriate. Do not force mappings where they are weak.

Example:

```md
# MITRE ATT&CK Coverage

| PCAPCase behavior | ATT&CK technique | Tactic | Confidence |
| --- | --- | --- | --- |
| HTTP executable download | T1105 Ingress Tool Transfer | Command and Control | Medium |
| ICMP/ARP internal sweep | T1018 Remote System Discovery | Discovery | Medium |
| DNS tunneling suspect | T1071.004 DNS | Command and Control | Low until confirmed |
| HTTP exfil upload | T1041 Exfiltration Over C2 Channel | Exfiltration | Medium |
| Cleartext credential observed | T1552 Unsecured Credentials | Credential Access | Context-dependent |
```

## `mapping/detection-taxonomy.yaml`

Machine-readable detector registry.

```yaml
detectors:
  suspicious_executable_download:
    category: malware-delivery
    module: pcapcase.detectors.download
    status: planned
    min_version: 0.2.0
    mitre:
      - id: T1105
        name: Ingress Tool Transfer
        confidence: medium
    required_protocols:
      - http
    output:
      - finding
      - extracted_object
      - indicator
```

## `mapping/tshark-field-map.yaml`

Track which TShark fields power each parser.

```yaml
http:
  request:
    - frame.number
    - frame.time_utc
    - ip.src
    - ip.dst
    - tcp.stream
    - http.request.method
    - http.request.full_uri
    - http.host
    - http.user_agent
  response:
    - frame.number
    - frame.time_utc
    - ip.src
    - ip.dst
    - tcp.stream
    - http.response.code
    - http.content_type
    - http.content_length
```

---

# 7. Design docs

PCAPCase should include design docs before implementation gets messy.

## `docs/output-schema.md`

Documents JSON and CSV output.

Sections:

- `case.json`
- `findings.json`
- `iocs.json`
- `hosts.csv`
- `timeline.csv`
- `extracted-files/manifest.json`

## `docs/tshark-fields.md`

Documents:

- Required TShark version
- Protocol fields used
- Known field differences between versions
- Fallback behavior when fields are missing

## `docs/limitations.md`

Be honest:

- Encrypted traffic limits visibility.
- NAT may hide host identity.
- Missing packets can break stream reconstruction.
- PCAPCase reports suspicious behavior, not final attribution.
- Some ATT&CK mappings are contextual.

## `docs/examples.md`

Shows sanitized sample output:

```bash
pcapcase analyze examples/sample.pcap --output examples/sample-case
```

Then screenshots or snippets:

- Findings summary
- Timeline rows
- Host inventory
- IOC JSON
- Report excerpt

---

# 8. Data model design

## Core entities

```text
CaseResult
├── CaptureMetadata
├── Host[]
├── NetworkEvent[]
├── Indicator[]
├── ExtractedObject[]
├── Finding[]
└── RunMetadata
```

## Evidence

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

## Finding

```python
@dataclass
class Finding:
    id: str
    title: str
    description: str
    severity: Literal["critical", "high", "medium", "low", "info"]
    confidence: Literal["high", "medium", "low"]
    category: str
    first_seen: datetime
    last_seen: datetime
    source_hosts: list[str]
    destination_hosts: list[str]
    evidence: list[Evidence]
    recommendations: list[str]
```

## NetworkEvent

```python
@dataclass
class NetworkEvent:
    timestamp: datetime
    event_type: str
    src_ip: str | None
    src_port: int | None
    dst_ip: str | None
    dst_port: int | None
    protocol: str
    summary: str
    frame_number: int
    stream_id: int | None
    raw: dict[str, str]
```

## Indicator

```python
@dataclass
class Indicator:
    type: Literal["ip", "domain", "url", "hash", "filename", "user_agent", "sni"]
    value: str
    first_seen: datetime
    last_seen: datetime
    source: str
    evidence: list[Evidence]
```

---

# 9. CLI product design

## Main commands

```bash
pcapcase doctor
pcapcase analyze incident.pcap
pcapcase timeline incident.pcap
pcapcase hosts incident.pcap
pcapcase iocs incident.pcap
pcapcase extract incident.pcap
pcapcase report case.json
```

## Analyze command

```bash
pcapcase analyze incident.pcap \
  --output cases/incident-001 \
  --format markdown,json,csv \
  --extract-http \
  --redact-secrets
```

## Example terminal output

```text
PCAPCase 0.1.0

[+] TShark: 4.2.5
[+] Input: incident.pcap
[+] SHA256: b6014d9e1663415dfb9b716f7dcfe7cb6bb94e37a1530df484c236d9a46be323
[+] Frames: 8,189
[+] Duration: 165s
[+] Hosts: 14
[+] Timeline events: 236
[+] IOCs: 31
[+] Findings: 4

Findings:
  HIGH    Suspicious executable download       frame=7485 stream=57
  MEDIUM  Internal ARP sweep                   source=172.23.4.115
  MEDIUM  HTTP upload / possible exfiltration  frame=8076 stream=64
  LOW     Unusual User-Agent                   frame=8076

Output written to: cases/incident-001
```

---

# 10. Report design

## `report.md` outline

```md
# PCAPCase Report: incident.pcap

## Executive summary

## Capture details

## Key findings

## Timeline summary

## Host inventory

## Indicators of compromise

## Extracted objects

## Evidence and reproduction commands

## Limitations

## Appendix: full timeline
```

## Finding block format

```md
### HIGH: Suspicious executable download

**Summary:** Host `172.23.4.115` downloaded `syswor64.exe` from `172.23.4.107:8443` over HTTP.

| Field | Value |
| --- | --- |
| First seen | 2024-11-04T13:06:03Z |
| Source | 172.23.4.115 |
| Destination | 172.23.4.107:8443 |
| Frame | 7485 |
| TCP stream | 57 |
| Confidence | High |

**Evidence:**

```text
GET /syswor64.exe HTTP/1.1
Host: 172.23.4.107:8443
```

**Reproduce:**

```bash
tshark -r incident.pcap -Y "frame.number==7485" \
  -T fields -e frame.time_utc -e ip.src -e ip.dst -e http.request.full_uri
```
```

---

# 11. Security and privacy design

## Defaults

- Do not upload PCAP files.
- Do not execute extracted files.
- Redact secrets by default.
- Sanitize object filenames.
- Prevent path traversal.
- Store output only in user-selected directory.
- Use safe subprocess calls with argument arrays, not shell strings.

## Redaction examples

- `Authorization: Bearer <redacted>`
- `Cookie: session=<redacted>`
- `password=<redacted>`
- `token=<redacted>`

## Risk warning

Extracted files may be malicious. PCAPCase should display this clearly when carving objects.

---

# 12. MVP requirements

## Functional requirements

| ID | Requirement | Priority |
| --- | --- | --- |
| FR-001 | Validate TShark availability with `doctor` | Must |
| FR-002 | Read PCAP/PCAPNG metadata | Must |
| FR-003 | Calculate SHA-256 of input capture | Must |
| FR-004 | Generate DNS/HTTP/TLS/ARP/ICMP/TCP timeline | Must |
| FR-005 | Generate host inventory | Must |
| FR-006 | Extract IOCs | Must |
| FR-007 | Detect HTTP downloads and uploads | Must |
| FR-008 | Generate `report.md` | Must |
| FR-009 | Generate `timeline.csv` and `hosts.csv` | Must |
| FR-010 | Generate `findings.json` and `iocs.json` | Must |
| FR-011 | Include evidence references for findings | Must |
| FR-012 | Extract HTTP objects safely | Should |
| FR-013 | Detect ARP/ICMP sweep | Should |
| FR-014 | Redact secrets by default | Should |
| FR-015 | HTML report | Later |
| FR-016 | STIX export | Later |

## Non-functional requirements

| ID | Requirement | Priority |
| --- | --- | --- |
| NFR-001 | Works on Windows and Linux | Must |
| NFR-002 | Offline by default | Must |
| NFR-003 | No packet upload | Must |
| NFR-004 | Deterministic output for tests | Must |
| NFR-005 | Clear error messages | Must |
| NFR-006 | Minimal dependencies | Should |
| NFR-007 | CI tests | Should |
| NFR-008 | JSON schema stability after v1.0 | Later |

---

# 13. Roadmap

## v0.1: Core triage

- CLI scaffolding
- `doctor`
- TShark runner
- Capture summary
- Host inventory
- Timeline generation
- IOC extraction
- Basic download/upload identification
- Markdown report
- JSON/CSV outputs
- Synthetic tests

## v0.2: Detection pack

- ARP sweep detector
- ICMP sweep detector
- TCP scan detector
- Suspicious executable download detector
- HTTP upload / possible exfil detector
- Cleartext credential detector
- Confidence and severity rules
- Case Cards for every detector

## v0.3: Analyst workflow

- HTML report
- Filtering by host/time/protocol
- Re-run manifest
- Extracted object manifest
- Optional YARA scan for extracted files
- Better secret redaction controls

## v1.0: Stable tool

- Stable JSON schema
- Plugin interface
- STIX 2.1 export
- Docker image
- Release binaries where practical
- Full documentation site
- Public sample cases

---

# 14. Portfolio positioning

PCAPCase should be featured as a flagship cybersec project when it has:

- Real CLI output
- Sample sanitized report
- Methodology docs
- Case Cards
- Mapping coverage
- Tests and CI
- Clear README
- Screenshots or terminal demo

Portfolio description:

> PCAPCase is a network forensics CLI that turns PCAP files into timelines, host inventories, extracted files, IOCs, and evidence-backed findings. Built for SOC and DFIR workflows with frame-level reproduction commands.

Short homepage project copy:

> PCAP-to-report network forensics CLI with timelines, host inventory, IOCs, extracted objects, and evidence-backed findings.

---

# 15. Initial implementation handoff

Use this prompt when handing the project to a build workflow:

> Build PCAPCase v0.1 as a standalone Python CLI following `008-pcapcase-prd-and-repo-design.md`. Start with repository scaffolding, README, methodology docs, mapping docs, templates, data models, safe TShark runner, and `doctor`. Then implement capture summary, timeline, host inventory, IOC extraction, basic HTTP download/upload detection, and Markdown/JSON/CSV output. Keep dependencies minimal, support Windows and Linux, use synthetic fixtures only, do not upload PCAPs, do not execute extracted files, and ensure every finding includes frame-level evidence plus a reproducible TShark command.
