<p align="center">
  <h1 align="center">🦈 PCAPCase</h1>
  <p align="center"><strong>From raw packets to evidence-backed network timelines.</strong></p>
  <p align="center">
    Offline-first network forensics CLI that parses PCAP files into behavioral findings, investigation timelines, IOCs, and interactive HTML dashboards.
  </p>
  <p align="center">
    <a href="https://github.com/1tsprune/PCAPCase/releases"><img src="https://img.shields.io/github/v/tag/1tsprune/PCAPCase?style=flat-square&label=Release" alt="Release"></a>
    <a href="https://github.com/1tsprune/PCAPCase/blob/main/LICENSE"><img src="https://img.shields.io/github/license/1tsprune/PCAPCase?style=flat-square" alt="License"></a>
    <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.9%2B-blue?style=flat-square" alt="Python"></a>
  </p>
</p>

---

<table align="center">
  <tr>
    <td><img src="screenshots/1.png" alt="HTML Report Overview" width="400"/></td>
    <td><img src="screenshots/2.png" alt="Interactive VirusTotal Graph" width="400"/></td>
  </tr>
  <tr>
    <td><img src="screenshots/3.png" alt="AI Executive Summary" width="400"/></td>
    <td><img src="screenshots/4.png" alt="Timeline & IOC Extraction" width="400"/></td>
  </tr>
</table>

---

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
- [Example Terminal Output](#example-terminal-output)
- [Interactive HTML Dashboard](#interactive-html-dashboard)
- [Project Structure](#project-structure)
- [Methodology](#methodology)
- [Configuration](#configuration)
- [Contributing](#contributing)
- [Author](#author)
- [License](#license)

## Features

| Feature | Description |
|---|---|
| **Offline-First TShark Engine** | Parses PCAP files completely offline. Never uploads your raw packets or derived evidence anywhere. |
| **Behavioral Detection** | Flags ARP/ICMP sweeps, TCP port scans, cleartext credentials, and suspicious HTTP downloads. |
| **MITRE ATT&CK Mapping** | Automatically maps network behaviors to MITRE ATT&CK tactics and techniques inside findings. |
| **Safe IOC Extraction** | Carves files safely without execution and redacts sensitive secrets (cookies, passwords, tokens) by default. |
| **VirusTotal Enrichment** | Optional `--vt-enrich` flag generates interactive relationship graphs for IPs, domains, and hashes in HTML. |
| **AI Executive Summary** | Optional `--ai-summary` (OpenAI/Anthropic) using only safe, *redacted* metadata to summarize the case. |
| **Interactive HTML Dashboard** | Standalone report with sidebar navigation, dynamic pie charts, and integrated VT network graphs. |
| **Multi-Format Export** | Automatically generates `report.html`, `report.md`, `findings.json`, `timeline.csv`, and `iocs.json`. |

## Quick Start

### Prerequisites

- Python 3.9+
- **TShark** (Required for packet parsing)
  - Linux: `sudo apt install tshark`
  - Windows: Install Wireshark and ensure TShark is in your PATH.

### Installation

```bash
git clone https://github.com/1tsprune/PCAPCase.git
cd PCAPCase
python3 -m venv .venv
source .venv/bin/activate        # Linux / macOS
# .venv\Scripts\activate         # Windows
pip install -r requirements.txt
```

Verify your environment:
```bash
python3 src/pcapcase/cli.py doctor
```

### Basic Usage

```bash
python3 src/pcapcase/cli.py analyze evidence.pcap --output-dir ./results
```

### Full Example with Integrations

```bash
export VT_API_KEY="your_virustotal_key"
export OPENAI_API_KEY="your_openai_key"

python3 src/pcapcase/cli.py analyze evidence.pcap \
  --output-dir ./results \
  --ai-summary \
  --ai-provider openai \
  --vt-enrich
```

## CLI Reference

```
Usage: pcapcase [COMMAND] [OPTIONS]

Commands:
  analyze    Process a PCAP file and generate forensic outputs.
  doctor     Check environment and TShark dependencies.

Options for 'analyze':
  PCAP_FILE          Path to the .pcap or .pcapng file. [required]
  --output-dir       Directory to save reports and extracted data. [default: ./output]
  --ai-summary       Enable AI executive summary generation (Opt-in).
  --ai-provider      Choose provider for summary: [anthropic|openai]
  --vt-enrich        Enable VirusTotal relationship graph in HTML.
  --yara-rules       Path to a directory of YARA rules for payload scanning.
```

## Example Terminal Output

```
PCAPCase 1.1.0 🦈

[+] Input File: evidence.pcap
[+] Environment: TShark 4.0.x found.
[+] Privacy: Redaction active. AI & VT opt-in features enabled.

[+] Engine:
    - Packets Processed: 54,231
    - Timeline events correlated: 890
    - Extracted Objects: 12 (Saved to extracted-files/)
    - IOCs Discovered: 34

[+] Findings (Categorized):
  [Reconnaissance]     MED    Network Service Discovery (T1046)        (Frames: 12-45)
  [Execution]          HIGH   Suspicious Executable Download           (Frames: 512-530)
  [Credential Access]  CRIT   Cleartext Credentials Leaked [REDACTED]  (Frames: 890)

[+] Enrichment & AI:
    - VirusTotal: Fetched relationships for 3 external IPs.
    - AI Summary: Generated executive breakdown via OpenAI.

[+] Rendering HTML Dashboard... Done! 📊

Output written to: results/
  -> results/report.html (Interactive Dashboard)
  -> results/findings.json (Machine-readable)
```

## Interactive HTML Dashboard

The standalone HTML report (`report.html`) opens in any browser with no server required. It includes:

- **Executive Summary** — Metric cards, severity distribution charts, and AI-generated overview.
- **Findings Table** — Sortable list of behavioral detections mapped to MITRE ATT&CK.
- **VirusTotal Graph** — Interactive node graph mapping correlations between endpoints, hashes, and domains.
- **Activity Timeline** — Tabular chronology of significant network events.
- **Host & IOC Inventory** — Easily copyable IPs, domains, and extracted file hashes.

## Project Structure

```
PCAPCase/
├── pyproject.toml
├── README.md
├── LICENSE
├── requirements.txt
├── docs/
│   ├── index.md                 # Investigation methodology
│   ├── output-schema.md         # JSON/CSV schema contracts
│   └── limitations.md           # Safety & redaction limits
├── mapping/
│   ├── mitre-attack-coverage.md # ATT&CK support matrix
│   └── detection-taxonomy.yaml  # Machine-readable detector map
├── tests/                       # Unit tests & synthetic PCAPs
└── src/pcapcase/
    ├── cli.py                   # CLI entrypoint
    ├── capture.py               # TShark runner
    ├── models.py                # Pydantic data models
    ├── ai_summary.py            # Opt-in AI summary engine
    ├── detectors/
    │   ├── scan.py              # ARP, ICMP, TCP Port Scan
    │   ├── download.py          # HTTP payload carving
    │   ├── credentials.py       # Cleartext secret leak detection
    │   └── exfiltration.py      # HTTP upload anomalies
    └── output/
        ├── html.py              # Interactive dashboard renderer
        └── report.py            # Markdown & JSON outputs
```

## Methodology

PCAPCase follows a strict offline-first methodology designed for safety:

1. **Ingest & Verify** — Validates the PCAP and parses headers via TShark.
2. **Extract & Redact** — Identifies HTTP/DNS objects, carving files safely to disk and redacting strings (passwords, tokens).
3. **Detect** — Runs stateless behavioral detectors over the parsed network events.
4. **Enrich (Opt-in)** — Optionally queries VirusTotal API or generates AI summaries using *only* redacted metadata.
5. **Report** — Outputs standardized CSV timelines, JSON findings, and the final HTML dashboard.

## Configuration

PCAPCase relies on environment variables for its optional integrations. Never hardcode these in your terminal history.

```bash
# VirusTotal Enrichment (for Interactive Graphs)
export VT_API_KEY="your_api_key_here"

# AI Executive Summary
export OPENAI_API_KEY="your_openai_key"
export ANTHROPIC_API_KEY="your_anthropic_key"
```

*Note: If these keys are not set, the tool runs 100% offline and skips the respective modules.*

## Contributing

1. Fork the [repository](https://github.com/1tsprune/PCAPCase)
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Ensure you test your changes: `pytest tests/`
4. Commit your changes and open a Pull Request.

## Author

**Eky Januarta**
[1tsprune.com](https://1tsprune.com) | GitHub: [@1tsprune](https://github.com/1tsprune)

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
