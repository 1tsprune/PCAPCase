from __future__ import annotations

import json
import os
import re
import shutil
from pathlib import Path

from .models import ExtractedObject, utc_now
from .runner import TSharkRunner, sha256_file
from .schema import SCHEMA_VERSION

_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


def sanitize_filename(name: str | None, fallback: str = "object.bin") -> str:
    base = os.path.basename(name or fallback).strip().replace("\\", "/").split("/")[-1]
    base = _SAFE_NAME.sub("_", base).strip("._")
    if not base:
        base = fallback
    if base in {".", ".."}:
        base = fallback
    return base[:180]


def _unique_path(directory: Path, filename: str) -> Path:
    candidate = directory / filename
    stem = candidate.stem
    suffix = candidate.suffix
    counter = 1
    while candidate.exists():
        candidate = directory / f"{stem}-{counter}{suffix}"
        counter += 1
    return candidate


def ensure_under_directory(path: Path, directory: Path) -> None:
    resolved = path.resolve()
    root = directory.resolve()
    if resolved != root and root not in resolved.parents:
        raise ValueError(f"path traversal blocked: {path}")


def extract_http_objects(pcap_path: str | Path, output_dir: str | Path, runner: TSharkRunner) -> list[ExtractedObject]:
    target = Path(output_dir) / "extracted-files"
    target.mkdir(parents=True, exist_ok=True)
    before = {path.name for path in target.iterdir() if path.is_file()}
    runner.run(["-r", str(pcap_path), "--export-objects", f"http,{target}"])
    objects: list[ExtractedObject] = []
    for path in sorted(target.iterdir(), key=lambda p: p.name):
        if not path.is_file() or path.name == "manifest.json" or path.name in before:
            continue
        sanitized = sanitize_filename(path.name)
        destination = _unique_path(target, sanitized)
        ensure_under_directory(destination, target)
        if destination != path:
            shutil.move(str(path), str(destination))
        digest = sha256_file(destination)
        objects.append(
            ExtractedObject(
                sha256=digest,
                original_filename=sanitized,
                sanitized_filename=destination.name,
                size=destination.stat().st_size,
                source_frame=None,
                tcp_stream=None,
                extraction_timestamp=utc_now(),
                path=str(destination),
            )
        )
    write_extracted_manifest(target / "manifest.json", objects)
    return objects


def object_from_file(path: str | Path, source_frame: int | None = None, tcp_stream: int | None = None) -> ExtractedObject:
    file_path = Path(path)
    return ExtractedObject(
        sha256=sha256_file(file_path),
        original_filename=sanitize_filename(file_path.name),
        sanitized_filename=sanitize_filename(file_path.name),
        size=file_path.stat().st_size,
        source_frame=source_frame,
        tcp_stream=tcp_stream,
        extraction_timestamp=utc_now(),
        path=str(file_path),
    )


def write_extracted_manifest(path: str | Path, objects: list[ExtractedObject]) -> None:
    manifest_path = Path(path)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "schema_version": SCHEMA_VERSION,
        "objects": [obj.to_dict() for obj in sorted(objects, key=lambda item: (item.sha256, item.sanitized_filename))],
    }
    manifest_path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
