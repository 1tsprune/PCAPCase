from __future__ import annotations

import hashlib
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


class TSharkError(RuntimeError):
    pass


@dataclass(frozen=True)
class TSharkResult:
    args: list[str]
    stdout: str
    stderr: str
    returncode: int

    @property
    def rendered_command(self) -> str:
        return render_command(self.args)


def render_command(args: list[str]) -> str:
    rendered: list[str] = []
    for arg in args:
        if not arg:
            rendered.append("''")
        elif any(ch.isspace() for ch in arg) or any(ch in arg for ch in ['"', "'", "\\"]):
            rendered.append('"' + arg.replace('\\', '\\\\').replace('"', '\\"') + '"')
        else:
            rendered.append(arg)
    return " ".join(rendered)


class TSharkRunner:
    def __init__(self, executable: str = "tshark", timeout_seconds: int = 120) -> None:
        self.executable = executable
        self.timeout_seconds = timeout_seconds

    def available_path(self) -> str | None:
        return shutil.which(self.executable)

    def version(self) -> str:
        result = self.run(["-v"], check=False, timeout_seconds=30)
        if result.returncode != 0:
            raise TSharkError(result.stderr.strip() or "Unable to run tshark -v")
        return (result.stdout.splitlines() or [""])[0].strip()

    def command(self, pcap_path: str | Path, display_filter: str, fields: list[str]) -> list[str]:
        args = [self.executable, "-r", str(pcap_path)]
        if display_filter:
            args.extend(["-Y", display_filter])
        args.extend(["-T", "fields", "-E", "header=n", "-E", "separator=\t", "-E", "occurrence=f"])
        for field in fields:
            args.extend(["-e", field])
        return args

    def fields(self, pcap_path: str | Path, display_filter: str, fields: list[str]) -> tuple[list[dict[str, str]], str]:
        args = self.command(pcap_path, display_filter, fields)
        result = self.run(args[1:])
        rows: list[dict[str, str]] = []
        for line in result.stdout.splitlines():
            values = line.split("\t")
            if len(values) < len(fields):
                values.extend([""] * (len(fields) - len(values)))
            rows.append({field: values[index] for index, field in enumerate(fields)})
        return rows, result.rendered_command

    def run(self, args: list[str], check: bool = True, timeout_seconds: int | None = None) -> TSharkResult:
        full_args = [self.executable, *args]
        try:
            completed = subprocess.run(
                full_args,
                shell=False,
                text=True,
                capture_output=True,
                timeout=timeout_seconds or self.timeout_seconds,
            )
        except FileNotFoundError as exc:
            raise TSharkError(f"TShark executable not found: {self.executable}") from exc
        except subprocess.TimeoutExpired as exc:
            raise TSharkError(f"TShark command timed out: {render_command(full_args)}") from exc
        result = TSharkResult(full_args, completed.stdout, completed.stderr, completed.returncode)
        if check and completed.returncode != 0:
            raise TSharkError(completed.stderr.strip() or f"TShark failed: {result.rendered_command}")
        return result


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
