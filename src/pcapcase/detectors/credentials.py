from __future__ import annotations

import re

from pcapcase.models import Finding, Host, NetworkEvent
from pcapcase.redaction import Redactor

from .common import finding_from_events

SECRET_KEYS = re.compile(r"(?i)(authorization:|cookie:|password=|passwd=|pwd=|token=|api_key=|apikey=|secret=|Basic\s+[A-Za-z0-9+/=]+)")


def detect(events: list[NetworkEvent], hosts: list[Host]) -> list[Finding]:
    """Detect cleartext credential exposure while never storing secrets.

    False positives include test credentials, session identifiers that are not
    authentication material, internal labs, and redacted data already present in
    source traffic. Evidence values are replaced with redacted markers even when
    a raw event accidentally contains the original secret.
    """
    redactor = Redactor()
    findings: list[Finding] = []
    for event in sorted(events, key=lambda e: (e.timestamp, e.frame_number)):
        if event.protocol != "http":
            continue
        combined = "\n".join([event.summary, *event.raw.values()])
        if not SECRET_KEYS.search(combined):
            continue
        marker = _marker(combined, redactor)
        finding = finding_from_events(
            "cleartext-credential",
            "Cleartext credential observed",
            "HTTP traffic contains credential-like material. The secret value was redacted; use the frame reference to validate locally if authorized.",
            "high" if "authorization" in combined.lower() or "password" in combined.lower() else "medium",
            "high",
            "credential-leakage",
            [event],
            "http",
            marker,
            ["Move authentication to encrypted transport where possible.", "Rotate exposed credentials or tokens if the traffic is confirmed relevant."],
            [{"id": "T1552", "name": "Unsecured Credentials", "tactic": "Credential Access", "confidence": "medium"}],
        )
        findings.append(finding)
    return findings


def _marker(value: str, redactor: Redactor) -> str:
    redacted = redactor.redact(value)
    for token in ("Authorization:", "Cookie:", "password=", "passwd=", "pwd=", "token=", "api_key=", "apikey=", "secret=", "Basic "):
        if token.lower() in value.lower():
            if token.endswith("="):
                return f"{token}<redacted>"
            if token.lower() == "basic ":
                return "Basic <redacted>"
            return f"{token} <redacted>"
    return redacted[:120]
