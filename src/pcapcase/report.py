from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .models import CaseResult


@dataclass(frozen=True)
class ReportData:
    case: CaseResult
    rerun_manifest: dict[str, Any] | None = None


def build_report_data(case: CaseResult, rerun_manifest: dict[str, Any] | None = None) -> ReportData:
    return ReportData(case=case, rerun_manifest=rerun_manifest)
