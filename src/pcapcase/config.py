from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .redaction import RedactionRule, Redactor, load_redaction_rules


@dataclass(frozen=True)
class AppConfig:
    redact_secrets: bool = True
    redaction_rules_path: Path | None = None

    def redactor(self) -> Redactor:
        if not self.redact_secrets:
            return Redactor([])
        rules: list[RedactionRule] = load_redaction_rules(self.redaction_rules_path)
        return Redactor(rules)
