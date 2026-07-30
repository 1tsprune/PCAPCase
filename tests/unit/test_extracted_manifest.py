import json
from pathlib import Path

from pcapcase.extract import object_from_file, sanitize_filename, write_extracted_manifest


def test_sanitize_filename_blocks_traversal():
    assert sanitize_filename("../../evil.exe") == "evil.exe"
    assert sanitize_filename("..") == "object.bin"


def test_write_extracted_manifest(tmp_path: Path):
    sample = tmp_path / "payload.bin"
    sample.write_bytes(b"abc")
    obj = object_from_file(sample, source_frame=7, tcp_stream=2)
    manifest = tmp_path / "manifest.json"
    write_extracted_manifest(manifest, [obj])
    data = json.loads(manifest.read_text())
    assert data["schema_version"] == "1.0"
    assert data["objects"][0]["sha256"] == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert data["objects"][0]["source_frame"] == 7
