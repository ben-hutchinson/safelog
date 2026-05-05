from pathlib import Path

import pytest

from safelog.rules import RulesConfigError, load_custom_rules


def test_load_custom_rules_from_explicit_config(tmp_path: Path) -> None:
    config = tmp_path / "safelog.toml"
    config.write_text(
        """
[rules.company_token]
pattern = "COMPANY_[A-Z0-9]{20}"
placeholder = "COMPANY_TOKEN"
severity = "warn"
description = "Internal company token"
""",
        encoding="utf-8",
    )

    rules = load_custom_rules(config_path=config)

    assert len(rules) == 1
    assert rules[0].name == "company_token"
    assert rules[0].key == "custom_company_token"
    assert rules[0].placeholder == "COMPANY_TOKEN"
    assert rules[0].severity == "warn"
    assert rules[0].pattern.pattern == "COMPANY_[A-Z0-9]{20}"


def test_load_custom_rules_finds_config_upward(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = tmp_path / "safelog.toml"
    nested = tmp_path / "app" / "logs"
    nested.mkdir(parents=True)
    config.write_text(
        """
[rules.session_id]
pattern = "SESSION-[0-9]+"
""",
        encoding="utf-8",
    )
    monkeypatch.chdir(nested)

    rules = load_custom_rules()

    assert rules[0].name == "session_id"
    assert rules[0].placeholder == "SESSION_ID"
    assert rules[0].severity == "safe"


def test_load_custom_rules_missing_auto_config_returns_empty(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)

    assert load_custom_rules() == []


def test_load_custom_rules_rejects_invalid_rule_name(tmp_path: Path) -> None:
    config = tmp_path / "safelog.toml"
    config.write_text(
        """
[rules."Company Token"]
pattern = "COMPANY_[A-Z0-9]+"
""",
        encoding="utf-8",
    )

    with pytest.raises(RulesConfigError, match="Invalid rule name"):
        load_custom_rules(config_path=config)


def test_load_custom_rules_rejects_invalid_regex(tmp_path: Path) -> None:
    config = tmp_path / "safelog.toml"
    config.write_text(
        """
[rules.company_token]
pattern = "["
""",
        encoding="utf-8",
    )

    with pytest.raises(RulesConfigError, match="Invalid regex"):
        load_custom_rules(config_path=config)


def test_load_custom_rules_rejects_missing_pattern(tmp_path: Path) -> None:
    config = tmp_path / "safelog.toml"
    config.write_text(
        """
[rules.company_token]
severity = "warn"
""",
        encoding="utf-8",
    )

    with pytest.raises(RulesConfigError, match="requires a string pattern"):
        load_custom_rules(config_path=config)


def test_load_custom_rules_rejects_invalid_severity(tmp_path: Path) -> None:
    config = tmp_path / "safelog.toml"
    config.write_text(
        """
[rules.company_token]
pattern = "COMPANY_[A-Z0-9]+"
severity = "critical"
""",
        encoding="utf-8",
    )

    with pytest.raises(RulesConfigError, match="Invalid severity"):
        load_custom_rules(config_path=config)
