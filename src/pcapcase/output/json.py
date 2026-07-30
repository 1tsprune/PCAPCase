from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pcapcase.models import CaseResult, Finding, Indicator, to_jsonable


def write_json(path: str | Path, data: Any) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(to_jsonable(data), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_case(path: str | Path, case: CaseResult) -> None:
    write_json(path, case.to_dict())


def write_findings(path: str | Path, findings: list[Finding]) -> None:
    write_json(path, [finding.to_dict() for finding in sorted(findings, key=lambda f: (f.first_seen, f.id))])


def write_iocs(path: str | Path, indicators: list[Indicator]) -> None:
    write_json(path, [indicator.to_dict() for indicator in sorted(indicators, key=lambda i: (i.type, i.value))])
