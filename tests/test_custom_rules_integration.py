import json
from pathlib import Path

from typer.testing import CliRunner

from safelog.main import app
from safelog.redactor import redact_text
from safelog.rules import CustomRule
from safelog.safety import check_safety
from safelog.scanner import scan_text


runner = CliRunner()


def company_rule(severity: str = "safe") -> CustomRule:
    return CustomRule.from_config(
        name="company_token",
        pattern="COMPANY_[A-Z0-9]{20}",
        placeholder="COMPANY_TOKEN",
        severity=severity,
        description="Internal company token",
    )


def test_scanner_counts_custom_rules_with_stable_key() -> None:
    result = scan_text("token=COMPANY_ABCDEFGHIJKLMNOPQRST\n", [company_rule()])

    assert result["custom_company_token"] == 1
    assert result["emails"] == 0


def test_redactor_redacts_custom_rules_deterministically() -> None:
    result = redact_text(
        "a=COMPANY_ABCDEFGHIJKLMNOPQRST b=COMPANY_ABCDEFGHIJKLMNOPQRST\n",
        [company_rule()],
    )

    assert result == "a=[COMPANY_TOKEN_1] b=[COMPANY_TOKEN_1]\n"


def test_safety_warns_for_custom_warn_rule() -> None:
    rule = company_rule("warn")
    result = check_safety({"custom_company_token": 1}, [rule])

    assert result["status"] == "warn"
    assert "custom rule company_token" in result["reason"]


def test_safety_blocks_for_custom_block_rule() -> None:
    rule = company_rule("block")
    result = check_safety({"custom_company_token": 1}, [rule])

    assert result["status"] == "block"
    assert "custom rule company_token" in result["reason"]


def test_cli_scan_honors_explicit_config(tmp_path: Path) -> None:
    log = tmp_path / "app.log"
    config = tmp_path / "safelog.toml"
    log.write_text("token=COMPANY_ABCDEFGHIJKLMNOPQRST\n", encoding="utf-8")
    config.write_text(
        """
[rules.company_token]
pattern = "COMPANY_[A-Z0-9]{20}"
placeholder = "COMPANY_TOKEN"
severity = "warn"
""",
        encoding="utf-8",
    )

    result = runner.invoke(app, ["scan", str(log), "--config", str(config)])

    assert result.exit_code == 0
    assert "Custom Company Token" in result.output


def test_cli_redact_honors_explicit_config(tmp_path: Path) -> None:
    log = tmp_path / "app.log"
    config = tmp_path / "safelog.toml"
    log.write_text("token=COMPANY_ABCDEFGHIJKLMNOPQRST\n", encoding="utf-8")
    config.write_text(
        """
[rules.company_token]
pattern = "COMPANY_[A-Z0-9]{20}"
placeholder = "COMPANY_TOKEN"
""",
        encoding="utf-8",
    )

    result = runner.invoke(app, ["redact", str(log), "--config", str(config)])

    assert result.exit_code == 0
    assert result.output == "token=[COMPANY_TOKEN_1]\n"


def test_cli_analyze_blocks_custom_block_rule_by_default(tmp_path: Path) -> None:
    log = tmp_path / "app.log"
    config = tmp_path / "safelog.toml"
    log.write_text("ERROR token=COMPANY_ABCDEFGHIJKLMNOPQRST\n", encoding="utf-8")
    config.write_text(
        """
[rules.company_token]
pattern = "COMPANY_[A-Z0-9]{20}"
severity = "block"
""",
        encoding="utf-8",
    )

    result = runner.invoke(app, ["analyze", str(log), "--config", str(config)])

    assert result.exit_code == 1
    assert "custom rule company_token" in result.output


def test_cli_analyze_json_includes_custom_scan_results(tmp_path: Path) -> None:
    log = tmp_path / "app.log"
    config = tmp_path / "safelog.toml"
    log.write_text("ERROR token=COMPANY_ABCDEFGHIJKLMNOPQRST 500\n", encoding="utf-8")
    config.write_text(
        """
[rules.company_token]
pattern = "COMPANY_[A-Z0-9]{20}"
placeholder = "COMPANY_TOKEN"
severity = "warn"
""",
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "analyze",
            str(log),
            "--config",
            str(config),
            "--json",
            "--fail-on",
            "never",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["scan_results"]["custom_company_token"] == 1
    assert payload["safety"]["status"] == "warn"
    assert "COMPANY_ABCDEFGHIJKLMNOPQRST" not in payload["summary"]
    assert "[COMPANY_TOKEN_1]" in payload["top_errors"][0]["line"]


def test_cli_invalid_config_exits_with_code_two(tmp_path: Path) -> None:
    log = tmp_path / "app.log"
    config = tmp_path / "safelog.toml"
    log.write_text("ERROR timeout 500\n", encoding="utf-8")
    config.write_text(
        """
[rules.company_token]
pattern = "["
""",
        encoding="utf-8",
    )

    result = runner.invoke(app, ["analyze", str(log), "--config", str(config)])

    assert result.exit_code == 2
    assert "Config error:" in result.stderr
    assert "Invalid regex" in result.stderr
