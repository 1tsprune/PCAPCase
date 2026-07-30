from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


DEFAULT_RULES = [
    {"name": "authorization-header", "pattern": r"(?i)(Authorization:\s*)([^\r\n]+)", "replacement": r"\1<redacted>"},
    {"name": "cookie-header", "pattern": r"(?i)(Cookie:\s*)([^\r\n]+)", "replacement": r"\1<redacted>"},
    {"name": "password-parameter", "pattern": r"(?i)(password=)[^&\s]+", "replacement": r"\1<redacted>"},
    {"name": "passwd-parameter", "pattern": r"(?i)(passwd=)[^&\s]+", "replacement": r"\1<redacted>"},
    {"name": "pwd-parameter", "pattern": r"(?i)(pwd=)[^&\s]+", "replacement": r"\1<redacted>"},
    {"name": "token-parameter", "pattern": r"(?i)(token=)[^&\s]+", "replacement": r"\1<redacted>"},
    {"name": "api-key-parameter", "pattern": r"(?i)((?:api_key|apikey)=)[^&\s]+", "replacement": r"\1<redacted>"},
    {"name": "secret-parameter", "pattern": r"(?i)(secret=)[^&\s]+", "replacement": r"\1<redacted>"},
    {"name": "basic-auth", "pattern": r"(?i)(Basic\s+)[A-Za-z0-9+/=]+", "replacement": r"\1<redacted>"},
]


@dataclass(frozen=True)
class RedactionRule:
    name: str
    pattern: str
    replacement: str

    def compile(self) -> re.Pattern[str]:
        return re.compile(self.pattern)


class Redactor:
    def __init__(self, rules: list[RedactionRule] | None = None) -> None:
        self.rules = rules if rules is not None else [RedactionRule(**rule) for rule in DEFAULT_RULES]
        self._compiled = [(rule, rule.compile()) for rule in self.rules]

    def redact(self, value: str | None) -> str:
        if value is None:
            return ""
        text = str(value)
        for rule, pattern in self._compiled:
            text = pattern.sub(rule.replacement, text)
        return text

    def has_secret(self, value: str | None) -> bool:
        if not value:
            return False
        text = str(value)
        return any(pattern.search(text) for _, pattern in self._compiled)


def load_redaction_rules(path: str | Path | None) -> list[RedactionRule]:
    if path is None:
        return [RedactionRule(**rule) for rule in DEFAULT_RULES]
    rule_path = Path(path)
    if not rule_path.exists():
        raise ValueError(f"Redaction rules file does not exist: {rule_path}")
    text = rule_path.read_text(encoding="utf-8")
    parsed = _parse_strict_rules_yaml(text)
    rules = [RedactionRule(**rule) for rule in parsed]
    for rule in rules:
        rule.compile()
    return rules


def _parse_strict_rules_yaml(text: str) -> list[dict[str, str]]:
    """Parse the tiny YAML subset shipped by PCAPCase.

    Supported shape only:

    rules:
      - name: example
        pattern: 'regex'
        replacement: '<redacted>'

    This avoids adding PyYAML for one simple local config file while failing
    closed on unsupported structures.
    """
    rules: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    saw_root = False
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped == "rules:":
            saw_root = True
            continue
        if not saw_root:
            raise ValueError("redaction rules must start with 'rules:'")
        if stripped.startswith("- "):
            if current:
                rules.append(current)
            current = {}
            remainder = stripped[2:].strip()
            if remainder:
                key, value = _split_yaml_pair(remainder)
                current[key] = _unquote(value)
            continue
        if current is None:
            raise ValueError("rule entries must start with '- name: ...'")
        key, value = _split_yaml_pair(stripped)
        current[key] = _unquote(value)
    if current:
        rules.append(current)
    if not rules:
        raise ValueError("redaction rules file did not define any rules")
    required = {"name", "pattern", "replacement"}
    for rule in rules:
        missing = required - set(rule)
        if missing:
            raise ValueError(f"redaction rule missing keys: {', '.join(sorted(missing))}")
        extra = set(rule) - required
        if extra:
            raise ValueError(f"redaction rule has unsupported keys: {', '.join(sorted(extra))}")
    return rules


def _split_yaml_pair(text: str) -> tuple[str, str]:
    if ":" not in text:
        raise ValueError(f"invalid redaction rule line: {text}")
    key, value = text.split(":", 1)
    key = key.strip()
    value = value.strip()
    if key not in {"name", "pattern", "replacement"}:
        raise ValueError(f"unsupported redaction rule key: {key}")
    return key, value


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value
