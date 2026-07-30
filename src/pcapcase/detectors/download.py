from __future__ import annotations

from urllib.parse import urlparse

from pcapcase.models import Finding, Host, NetworkEvent
from pcapcase.plugins import Detector, DetectorContext

from .common import finding_from_events, is_private_ip

EXECUTABLE_EXTENSIONS = {".exe", ".dll", ".scr", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".elf", ".sh"}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz"}
DOCUMENT_EXTENSIONS = {".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm", ".rtf"}
SUSPICIOUS_CONTENT_TYPES = {"application/x-msdownload", "application/octet-stream", "application/x-dosexec", "application/java-archive", "application/zip"}


class SuspiciousDownloadDetector(Detector):
    id = "builtin.suspicious_http_download"
    name = "Suspicious HTTP download"
    version = "1.0"
    categories = ("malware-delivery", "http-download")

    def detect(self, events: list[NetworkEvent], hosts: list[Host], context: DetectorContext) -> list[Finding]:
        """Detect suspicious executable/script/archive downloads.

        False positives: software updates, internal repositories, admin tooling,
        package managers, and normal browser downloads. Severity increases when
        a payload-like extension or content type is fetched from an external host.
        """
        findings: list[Finding] = []
        for event in sorted(events, key=lambda e: (e.timestamp, e.frame_number)):
            if event.protocol != "http" or event.event_type != "http_request":
                continue
            method = (event.raw.get("http.request.method") or "").upper()
            if method != "GET":
                continue
            uri = event.raw.get("http.request.full_uri") or ""
            filename = _filename_from_uri(uri)
            extension = _extension(filename)
            content_type = (event.raw.get("http.content_type") or "").lower()
            if extension not in EXECUTABLE_EXTENSIONS | ARCHIVE_EXTENSIONS | DOCUMENT_EXTENSIONS and content_type not in SUSPICIOUS_CONTENT_TYPES:
                continue
            external = not is_private_ip(event.dst_ip)
            severity = "high" if extension in EXECUTABLE_EXTENSIONS and external else "medium" if extension in EXECUTABLE_EXTENSIONS | ARCHIVE_EXTENSIONS else "low"
            confidence = "high" if extension in EXECUTABLE_EXTENSIONS else "medium"
            title = "Suspicious executable download" if extension in EXECUTABLE_EXTENSIONS else "Suspicious file download"
            findings.append(
                finding_from_events(
                    "download",
                    title,
                    f"HTTP GET requested {filename or uri or 'a file'} with extension/content type associated with executable, script, archive, or macro-capable content.",
                    severity,
                    confidence,
                    "malware-delivery",
                    [event],
                    "http.request.full_uri",
                    uri,
                    ["Confirm whether the download was user-initiated or an approved update.", "If an object was carved, hash and analyze it in a safe offline lab without executing it."],
                    [{"id": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command and Control", "confidence": "medium"}],
                )
            )
        return findings


def detect(events: list[NetworkEvent], hosts: list[Host]) -> list[Finding]:
    return SuspiciousDownloadDetector().detect(events, hosts, DetectorContext("1.0.0"))


def _filename_from_uri(uri: str) -> str:
    path = urlparse(uri).path if uri else ""
    return path.rstrip("/").split("/")[-1]


def _extension(filename: str) -> str:
    if "." not in filename:
        return ""
    return "." + filename.rsplit(".", 1)[-1].lower()
