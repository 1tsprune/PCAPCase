from __future__ import annotations

"""Optional local-only YARA scanning for extracted files.

Design reviewed inline before implementation:
- Rules are loaded only from a local file or local directory supplied via
  --yara-rules; no remote feeds, downloads, or network access are used.
- Scanning reads bytes from extracted files and never executes them.
- yara-python is used when installed. If it is absent, PCAPCase falls back to a
  local `yara` CLI executable using subprocess argument arrays with shell=False.
- A YARA match becomes a Finding with evidence tied to the extracted object
  metadata. If source frame/stream is unknown, the evidence frame is 0 and the
  filename/hash point to the object manifest entry.
- YARA compile/runtime errors do not disable redaction or extraction. They raise
  YaraScanError with a clear local error; the CLI reports it and continues the
  base analysis without YARA findings.
"""

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from .models import Evidence, ExtractedObject, Finding, utc_now
from .runner import render_command


class YaraScanError(RuntimeError):
    pass


def scan_extracted_objects(objects: list[ExtractedObject], rules_path: str | Path) -> list[Finding]:
    rules = Path(rules_path)
    if not rules.exists():
        raise YaraScanError(f"YARA rules path does not exist: {rules}")
    if not objects:
        return []
    try:
        return _scan_with_yara_python(objects, rules)
    except ImportError:
        return _scan_with_cli(objects, rules)


def _rule_files(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    files = [item for item in path.rglob("*") if item.is_file() and item.suffix.lower() in {".yar", ".yara"}]
    if not files:
        raise YaraScanError(f"No .yar or .yara files found under {path}")
    return sorted(files, key=lambda p: str(p))


def _scan_with_yara_python(objects: list[ExtractedObject], rules_path: Path) -> list[Finding]:
    try:
        import yara  # type: ignore[import-not-found]
    except ImportError:
        raise
    files = _rule_files(rules_path)
    try:
        compiled = yara.compile(filepaths={str(index): str(path) for index, path in enumerate(files)})
    except Exception as exc:
        raise YaraScanError(f"YARA rule compile failed: {exc}") from exc
    findings: list[Finding] = []
    for obj in sorted(objects, key=lambda item: (item.sha256, item.sanitized_filename)):
        try:
            matches = compiled.match(str(obj.path))
        except Exception as exc:
            raise YaraScanError(f"YARA scan failed for {obj.sanitized_filename}: {exc}") from exc
        if matches:
            findings.append(_finding_from_matches(obj, [str(match.rule) for match in matches], "yara-python"))
    return findings


def _scan_with_cli(objects: list[ExtractedObject], rules_path: Path) -> list[Finding]:
    executable = shutil.which("yara")
    if not executable:
        raise YaraScanError("YARA requested but neither yara-python nor local yara CLI is available")
    files = _rule_files(rules_path)
    findings: list[Finding] = []
    for obj in sorted(objects, key=lambda item: (item.sha256, item.sanitized_filename)):
        matched_rules: list[str] = []
        for rule_file in files:
            args = [executable, str(rule_file), str(obj.path)]
            try:
                completed = subprocess.run(args, shell=False, text=True, capture_output=True, timeout=60)
            except subprocess.TimeoutExpired as exc:
                raise YaraScanError(f"YARA command timed out: {render_command(args)}") from exc
            if completed.returncode not in {0, 1}:
                raise YaraScanError(completed.stderr.strip() or f"YARA command failed: {render_command(args)}")
            for line in completed.stdout.splitlines():
                if line.strip():
                    matched_rules.append(line.split()[0])
        if matched_rules:
            findings.append(_finding_from_matches(obj, sorted(set(matched_rules)), "yara-cli"))
    return findings


def _finding_from_matches(obj: ExtractedObject, matches: list[str], engine: str) -> Finding:
    now = utc_now()
    frame = obj.source_frame or 0
    evidence = Evidence(
        frame_number=frame,
        timestamp=obj.extraction_timestamp,
        protocol="file",
        tcp_stream=obj.tcp_stream,
        field="extracted_object.sha256",
        value=f"{obj.sha256} matches={','.join(matches)}",
        reproduction_command=f"yara <local-rules> {obj.sanitized_filename}",
    )
    return Finding(
        id=f"yara-{obj.sha256[:12]}",
        title="YARA match on extracted object",
        description=f"Extracted object {obj.sanitized_filename} matched local YARA rule(s): {', '.join(matches)}. The file was scanned as bytes only and was not executed.",
        severity="medium",
        confidence="medium",
        category="malware-analysis",
        first_seen=obj.extraction_timestamp,
        last_seen=obj.extraction_timestamp,
        source_hosts=[],
        destination_hosts=[],
        evidence=[evidence],
        recommendations=["Validate the rule match in an isolated offline analysis environment.", "Do not execute the extracted object."],
        mitre_attack=[],
    )


def matches_to_manifest_metadata(findings: list[Finding]) -> list[dict[str, Any]]:
    return [finding.to_dict() for finding in sorted(findings, key=lambda item: item.id)]
