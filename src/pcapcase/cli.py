from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from . import __version__
from .capture import read_capture_metadata
from .config import AppConfig
from .detectors import run_all
from .extract import extract_http_objects, write_extracted_manifest
from .filters import filter_events, parse_protocols
from .hosts import build_hosts
from .iocs import extract_iocs
from .manifest import build_rerun_manifest, write_rerun_manifest
from .models import CaseResult, RunMetadata, parse_datetime, utc_now
from .output import csv as csv_output
from .output import html as html_output
from .output import json as json_output
from .output import markdown as markdown_output
from .report import build_report_data
from .runner import TSharkError, TSharkRunner, sha256_file
from .timeline import build_timeline
from .yara_scan import YaraScanError, scan_extracted_objects

MIN_TSHARK_VERSION = (4, 2, 0)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pcapcase", description="Offline PCAP triage and evidence-backed reporting")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("doctor", help="Check local dependencies")
    analyze = sub.add_parser("analyze", help="Analyze a PCAP/PCAPNG")
    analyze.add_argument("pcap")
    analyze.add_argument("--output", "-o", default="case")
    analyze.add_argument("--extract-http", action="store_true")
    analyze.add_argument("--html", action="store_true")
    analyze.add_argument("--host")
    analyze.add_argument("--start")
    analyze.add_argument("--end")
    analyze.add_argument("--protocol")
    analyze.add_argument("--redaction-rules")
    analyze.add_argument("--no-redact-secrets", action="store_true")
    analyze.add_argument("--yara-rules")
    analyze.add_argument("--ai-summary", action="store_true")
    analyze.add_argument("--ai-provider", choices=["anthropic", "openai"])
    for name in ("timeline", "hosts", "iocs"):
        cmd = sub.add_parser(name, help=f"Generate {name} output")
        cmd.add_argument("pcap")
        cmd.add_argument("--output", "-o", default=".")
        cmd.add_argument("--host")
        cmd.add_argument("--start")
        cmd.add_argument("--end")
        cmd.add_argument("--protocol")
        cmd.add_argument("--redaction-rules")
    extract = sub.add_parser("extract", help="Safely extract HTTP objects")
    extract.add_argument("pcap")
    extract.add_argument("--output", "-o", default="case")
    report = sub.add_parser("report", help="Render report from case.json")
    report.add_argument("case_json")
    report.add_argument("--output", "-o", default="report.md")
    report.add_argument("--ai-summary", action="store_true")
    report.add_argument("--ai-provider", choices=["anthropic", "openai"])
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "doctor":
            return doctor()
        if args.command == "analyze":
            return analyze(args, argv if argv is not None else sys.argv[1:])
        if args.command in {"timeline", "hosts", "iocs"}:
            return focused_output(args)
        if args.command == "extract":
            runner = TSharkRunner()
            objects = extract_http_objects(args.pcap, args.output, runner)
            print(f"Extracted objects: {len(objects)}")
            return 0
        if args.command == "report":
            return render_report(args)
    except (TSharkError, ValueError, YaraScanError) as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2
    return 1


def doctor() -> int:
    runner = TSharkRunner()
    print(f"PCAPCase {__version__}")
    print(f"Python: {sys.version.split()[0]}")
    path = runner.available_path()
    if not path:
        print("TShark: not found", file=sys.stderr)
        _print_tshark_install_hint()
        return 1
    print(f"TShark path: {path}")
    version_text = runner.version()
    print(f"TShark version: {version_text}")
    version = _parse_tshark_version(version_text)
    if version is not None and version < MIN_TSHARK_VERSION:
        required = ".".join(str(part) for part in MIN_TSHARK_VERSION)
        found = ".".join(str(part) for part in version)
        print(f"TShark: version {found} is below required {required}", file=sys.stderr)
        _print_tshark_install_hint()
        return 1
    print("Offline mode: enforced by design; no upload features are implemented")
    return 0


def _parse_tshark_version(version_text: str) -> tuple[int, int, int] | None:
    match = re.search(r"TShark \(Wireshark\) (\d+)\.(\d+)\.(\d+)", version_text)
    if not match:
        return None
    return tuple(int(part) for part in match.groups())


def _print_tshark_install_hint() -> None:
    print("\nPlease install or update tshark manually to use PCAPCase:", file=sys.stderr)
    if sys.platform == "win32":
        print("  Windows: choco install wireshark OR winget install WiresharkFoundation.Wireshark", file=sys.stderr)
    elif sys.platform == "darwin":
        print("  macOS:   brew install wireshark", file=sys.stderr)
    else:
        print("  Linux:   sudo apt install tshark OR sudo dnf install wireshark-cli", file=sys.stderr)


def analyze(args: argparse.Namespace, cli_args: list[str]) -> int:
    pcap = Path(args.pcap)
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    runner = TSharkRunner()
    config = AppConfig(redact_secrets=not args.no_redact_secrets, redaction_rules_path=Path(args.redaction_rules) if args.redaction_rules else None)
    redactor = config.redactor()
    capture = read_capture_metadata(pcap, runner)
    events = build_timeline(pcap, runner, redactor)
    events = _apply_filters(events, args)
    hosts = build_hosts(events)
    indicators = extract_iocs(events)
    extracted = extract_http_objects(pcap, output_dir, runner) if args.extract_http else []
    findings = run_all(events, hosts)
    if args.yara_rules:
        if not extracted:
            print("[!] --yara-rules was provided but no extracted objects exist; use --extract-http to carve HTTP objects first", file=sys.stderr)
        else:
            try:
                findings.extend(scan_extracted_objects(extracted, args.yara_rules))
            except YaraScanError as exc:
                print(f"[!] YARA skipped: {exc}", file=sys.stderr)
    run = RunMetadata(__version__, utc_now(), cli_args, capture.tshark_version, capture.sha256, str(output_dir))
    case = CaseResult(capture, hosts, events, indicators, extracted, sorted(findings, key=lambda f: (f.first_seen, f.id)), run)
    manifest = build_rerun_manifest(
        input_path=pcap,
        input_sha256=capture.sha256,
        tshark_version=capture.tshark_version,
        cli_args=cli_args,
        output_directory=output_dir,
        filters={"host": args.host, "start": args.start, "end": args.end, "protocol": args.protocol},
        optional_features={"extract_http": bool(args.extract_http), "html": bool(args.html), "yara": bool(args.yara_rules), "redaction": not args.no_redact_secrets},
    )
    manifest_dict = manifest.to_dict()
    write_rerun_manifest(output_dir / "rerun-manifest.json", manifest)
    json_output.write_case(output_dir / "case.json", case)
    json_output.write_findings(output_dir / "findings.json", case.findings)
    json_output.write_iocs(output_dir / "iocs.json", case.indicators)
    csv_output.write_timeline(output_dir / "timeline.csv", case.events)
    csv_output.write_hosts(output_dir / "hosts.csv", case.hosts)
    if extracted:
        write_extracted_manifest(output_dir / "extracted-files" / "manifest.json", extracted)
    else:
        (output_dir / "extracted-files").mkdir(parents=True, exist_ok=True)
        write_extracted_manifest(output_dir / "extracted-files" / "manifest.json", [])
    report_data = build_report_data(case, manifest_dict)
    markdown_output.write_report(output_dir / "report.md", report_data)
    if getattr(args, "ai_summary", False) and getattr(args, "ai_provider", None):
        print(f"[!] --ai-summary is currently unimplemented, no summary generated", file=sys.stderr)
    if getattr(args, "html", False):
        html_output.write_report(output_dir / "report.html", report_data)
    print(f"PCAPCase {__version__}")
    print(f"[+] Input: {pcap}")
    print(f"[+] SHA256: {capture.sha256}")
    print(f"[+] Hosts: {len(hosts)}")
    print(f"[+] Timeline events: {len(events)}")
    print(f"[+] IOCs: {len(indicators)}")
    print(f"[+] Findings: {len(case.findings)}")
    print(f"[+] Output written to: {output_dir}")
    return 0


def focused_output(args: argparse.Namespace) -> int:
    runner = TSharkRunner()
    config = AppConfig(redaction_rules_path=Path(args.redaction_rules) if args.redaction_rules else None)
    events = _apply_filters(build_timeline(args.pcap, runner, config.redactor()), args)
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    if args.command == "timeline":
        csv_output.write_timeline(output / "timeline.csv", events)
    elif args.command == "hosts":
        csv_output.write_hosts(output / "hosts.csv", build_hosts(events))
    elif args.command == "iocs":
        json_output.write_iocs(output / "iocs.json", extract_iocs(events))
    return 0


def render_report(args: argparse.Namespace) -> int:
    output_dir = Path(args.output).parent
    if getattr(args, "ai_summary", False) and getattr(args, "ai_provider", None):
        print(f"[!] --ai-summary is currently unimplemented, no summary generated", file=sys.stderr)
    return 0
    return filter_events(
        events,
        host=getattr(args, "host", None),
        start=parse_datetime(getattr(args, "start", None)),
        end=parse_datetime(getattr(args, "end", None)),
        protocols=parse_protocols(getattr(args, "protocol", None)),
    )


def _apply_filters(events, args):
    return filter_events(
        events,
        host=getattr(args, "host", None),
        start=parse_datetime(getattr(args, "start", None)),
        end=parse_datetime(getattr(args, "end", None)),
        protocols=parse_protocols(getattr(args, "protocol", None)),
    )

if __name__ == "__main__":
    raise SystemExit(main())
