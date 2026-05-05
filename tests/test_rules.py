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


def test_load_custom_rules_from_rules_array_schema(tmp_path: Path) -> None:
    config = tmp_path / "safelog.toml"
    config.write_text(
        """
[[rules]]
name = "stripe_secret_key"
pattern = "sk_live_[A-Za-z0-9]+"
label = "STRIPE_KEY"
severity = "block"

[[rules]]
name = "internal_user_id"
pattern = "user_[0-9]+"
label = "USER_ID"
severity = "warn"
""",
        encoding="utf-8",
    )

    rules = load_custom_rules(config_path=config)

    assert [rule.name for rule in rules] == [
        "stripe_secret_key",
        "internal_user_id",
    ]
    assert [rule.key for rule in rules] == [
        "custom_stripe_secret_key",
        "custom_internal_user_id",
    ]
    assert [rule.placeholder for rule in rules] == ["STRIPE_KEY", "USER_ID"]
    assert [rule.severity for rule in rules] == ["block", "warn"]


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


def test_load_custom_rules_rejects_non_string_label(tmp_path: Path) -> None:
    config = tmp_path / "safelog.toml"
    config.write_text(
        """
[[rules]]
name = "stripe_secret_key"
pattern = "sk_live_[A-Za-z0-9]+"
label = 123
""",
        encoding="utf-8",
    )

    with pytest.raises(RulesConfigError, match="Invalid label"):
        load_custom_rules(config_path=config)


def test_load_custom_rules_rejects_conflicting_label_and_placeholder(
    tmp_path: Path,
) -> None:
    config = tmp_path / "safelog.toml"
    config.write_text(
        """
[[rules]]
name = "stripe_secret_key"
pattern = "sk_live_[A-Za-z0-9]+"
label = "STRIPE_KEY"
placeholder = "OTHER_KEY"
""",
        encoding="utf-8",
    )

    with pytest.raises(RulesConfigError, match="cannot define different label"):
        load_custom_rules(config_path=config)


def test_load_custom_rules_rejects_missing_name_in_rules_array(tmp_path: Path) -> None:
    config = tmp_path / "safelog.toml"
    config.write_text(
        """
[[rules]]
pattern = "sk_live_[A-Za-z0-9]+"
label = "STRIPE_KEY"
""",
        encoding="utf-8",
    )

    with pytest.raises(RulesConfigError, match="requires a string name"):
        load_custom_rules(config_path=config)


def test_load_custom_rules_rejects_duplicate_names_in_rules_array(
    tmp_path: Path,
) -> None:
    config = tmp_path / "safelog.toml"
    config.write_text(
        """
[[rules]]
name = "stripe_secret_key"
pattern = "sk_live_[A-Za-z0-9]+"

[[rules]]
name = "stripe_secret_key"
pattern = "sk_live_[A-Za-z0-9]+"
""",
        encoding="utf-8",
    )

    with pytest.raises(RulesConfigError, match="Duplicate rule name"):
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


def test_load_custom_rules_rejects_invalid_label(tmp_path: Path) -> None:
    config = tmp_path / "safelog.toml"
    config.write_text(
        """
[[rules]]
name = "stripe_secret_key"
pattern = "sk_live_[A-Za-z0-9]+"
label = "stripe-key"
""",
        encoding="utf-8",
    )

    with pytest.raises(RulesConfigError, match="Invalid label"):
        load_custom_rules(config_path=config)


def test_load_custom_rules_rejects_invalid_legacy_placeholder(
    tmp_path: Path,
) -> None:
    config = tmp_path / "safelog.toml"
    config.write_text(
        """
[rules.company_token]
pattern = "COMPANY_[A-Z0-9]+"
placeholder = "company-token"
""",
        encoding="utf-8",
    )

    with pytest.raises(RulesConfigError, match="Invalid placeholder"):
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


def test_load_custom_rules_rejects_non_table_rule_entry(tmp_path: Path) -> None:
    config = tmp_path / "safelog.toml"
    config.write_text(
        """
rules = ["not-a-table"]
""",
        encoding="utf-8",
    )

    with pytest.raises(RulesConfigError, match="Rule entry 1 must be a table"):
        load_custom_rules(config_path=config)


def test_load_custom_rules_rejects_non_table_legacy_rule(tmp_path: Path) -> None:
    config = tmp_path / "safelog.toml"
    config.write_text(
        """
[rules]
company_token = "not-a-table"
""",
        encoding="utf-8",
    )

    with pytest.raises(RulesConfigError, match="Rule company_token must be a table"):
        load_custom_rules(config_path=config)


def test_load_custom_rules_rejects_invalid_rules_container(tmp_path: Path) -> None:
    config = tmp_path / "safelog.toml"
    config.write_text(
        """
rules = "not-a-table"
""",
        encoding="utf-8",
    )

    with pytest.raises(RulesConfigError, match="Config rules must be"):
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


def test_load_custom_rules_rejects_non_string_severity(tmp_path: Path) -> None:
    config = tmp_path / "safelog.toml"
    config.write_text(
        """
[[rules]]
name = "stripe_secret_key"
pattern = "sk_live_[A-Za-z0-9]+"
severity = 123
""",
        encoding="utf-8",
    )

    with pytest.raises(RulesConfigError, match="Invalid severity"):
        load_custom_rules(config_path=config)


def test_load_custom_rules_rejects_invalid_description(tmp_path: Path) -> None:
    config = tmp_path / "safelog.toml"
    config.write_text(
        """
[[rules]]
name = "stripe_secret_key"
pattern = "sk_live_[A-Za-z0-9]+"
description = 123
""",
        encoding="utf-8",
    )

    with pytest.raises(RulesConfigError, match="Invalid description"):
        load_custom_rules(config_path=config)


def test_load_custom_rules_rejects_missing_explicit_config(tmp_path: Path) -> None:
    with pytest.raises(RulesConfigError, match="Config file not found"):
        load_custom_rules(config_path=tmp_path / "missing.toml")
