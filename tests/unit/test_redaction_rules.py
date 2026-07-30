from pathlib import Path

from pcapcase.redaction import Redactor, load_redaction_rules


def test_default_redacts_secrets():
    redactor = Redactor()
    assert redactor.redact("password=hunter2&x=1") == "password=<redacted>&x=1"
    assert redactor.redact("Authorization: Bearer abc") == "Authorization: <redacted>"


def test_custom_rules_yaml_subset(tmp_path: Path):
    rules = tmp_path / "rules.yaml"
    rules.write_text("""rules:\n  - name: custom\n    pattern: '(secret: )[A-Za-z]+'\n    replacement: '\\1<redacted>'\n""", encoding="utf-8")
    redactor = Redactor(load_redaction_rules(rules))
    assert redactor.redact("secret: value") == "secret: <redacted>"
