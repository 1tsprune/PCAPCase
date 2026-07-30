from __future__ import annotations

"""Stable detector plugin interface for PCAPCase v1.0.

Plugins receive normalized NetworkEvent and Host objects only. They are not given
PCAP paths, extracted-file paths, subprocess helpers, or execution hooks. This
keeps third-party detectors in the evidence/correlation layer and prevents the
plugin API from becoming a path to execute carved objects.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from importlib import metadata
from typing import Iterable

from .models import Finding, Host, NetworkEvent


@dataclass(frozen=True)
class DetectorContext:
    pcapcase_version: str
    enabled_detectors: tuple[str, ...] = ()


class Detector(ABC):
    """Base class for all PCAPCase detectors.

    A detector must be deterministic and side-effect free: same events and hosts
    produce the same findings. It must not perform network calls, run
    subprocesses, execute extracted files, or mutate global shared state.
    """

    id: str
    name: str
    version: str = "1.0"
    categories: tuple[str, ...] = ()

    @abstractmethod
    def detect(self, events: list[NetworkEvent], hosts: list[Host], context: DetectorContext) -> list[Finding]:
        """Return evidence-backed findings for normalized events and hosts."""


def builtin_detectors() -> list[Detector]:
    from .detectors.credentials import CleartextCredentialDetector
    from .detectors.download import SuspiciousDownloadDetector
    from .detectors.exfiltration import HttpExfiltrationDetector
    from .detectors.scan import ArpSweepDetector, IcmpSweepDetector, TcpPortScanDetector

    return [
        ArpSweepDetector(),
        IcmpSweepDetector(),
        TcpPortScanDetector(),
        SuspiciousDownloadDetector(),
        HttpExfiltrationDetector(),
        CleartextCredentialDetector(),
    ]


def entrypoint_detectors(group: str = "pcapcase.detectors") -> list[Detector]:
    detectors: list[Detector] = []
    try:
        entry_points = metadata.entry_points()
        selected = entry_points.select(group=group) if hasattr(entry_points, "select") else entry_points.get(group, [])
    except Exception:
        return detectors
    for entry_point in selected:
        loaded = entry_point.load()
        instance = loaded() if isinstance(loaded, type) else loaded
        if not isinstance(instance, Detector):
            raise TypeError(f"Entry point {entry_point.name} is not a PCAPCase Detector")
        detectors.append(instance)
    return sorted(detectors, key=lambda detector: detector.id)


def run_detectors(detectors: Iterable[Detector], events: list[NetworkEvent], hosts: list[Host], context: DetectorContext) -> list[Finding]:
    findings: list[Finding] = []
    for detector in sorted(detectors, key=lambda item: item.id):
        findings.extend(detector.detect(events, hosts, context))
    return sorted(findings, key=lambda finding: (finding.first_seen, finding.id, finding.title))
