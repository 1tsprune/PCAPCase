from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from . import __version__
from .models import format_datetime, utc_now
from .schema import SCHEMA_VERSION


@dataclass(frozen=True)
class RerunManifest:
    schema_version: str
    pcapcase_version: str
    run_timestamp: datetime
    input_path: str
    input_sha256: str
    tshark_version: str | None
    cli_args: list[str]
    output_directory: str
    python_version: str
    filters: dict[str, str | None]
    optional_features: dict[str, bool]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "pcapcase_version": self.pcapcase_version,
            "run_timestamp": format_datetime(self.run_timestamp),
            "input_path": self.input_path,
            "input_sha256": self.input_sha256,
            "tshark_version": self.tshark_version,
            "cli_args": list(self.cli_args),
            "output_directory": self.output_directory,
            "python_version": self.python_version,
            "filters": dict(sorted(self.filters.items())),
            "optional_features": dict(sorted(self.optional_features.items())),
        }


def build_rerun_manifest(
    input_path: str | Path,
    input_sha256: str,
    tshark_version: str | None,
    cli_args: list[str],
    output_directory: str | Path,
    filters: dict[str, str | None] | None = None,
    optional_features: dict[str, bool] | None = None,
    run_timestamp: datetime | None = None,
) -> RerunManifest:
    return RerunManifest(
        schema_version=SCHEMA_VERSION,
        pcapcase_version=__version__,
        run_timestamp=run_timestamp or utc_now(),
        input_path=str(input_path),
        input_sha256=input_sha256,
        tshark_version=tshark_version,
        cli_args=list(cli_args),
        output_directory=str(output_directory),
        python_version=sys.version.split()[0],
        filters=filters or {},
        optional_features=optional_features or {},
    )


def write_rerun_manifest(path: str | Path, manifest: RerunManifest) -> None:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(manifest.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
