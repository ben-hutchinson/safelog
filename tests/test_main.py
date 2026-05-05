import json
from pathlib import Path
from typing import Any

from typer.testing import CliRunner

from safelog.main import app


runner = CliRunner()


def write_log(tmp_path: Path, content: str) -> Path:
    log = tmp_path / "sample.log"
    log.write_text(content, encoding="utf-8")
    return log


def test_scan_command_runs(tmp_path: Path) -> None:
    log = write_log(tmp_path, "user=jane@example.com ip=10.0.0.1\n")

    result = runner.invoke(app, ["scan", str(log)])

    assert result.exit_code == 0
    assert "Scan Results" in result.output
    assert "Emails" in result.output
    assert "Ips" in result.output


def test_redact_command_writes_out_file(tmp_path: Path) -> None:
    log = write_log(tmp_path, "user=jane@example.com\n")
    out = tmp_path / "redacted.log"

    result = runner.invoke(app, ["redact", str(log), "--out", str(out)])

    assert result.exit_code == 0
    assert out.read_text(encoding="utf-8") == "user=[EMAIL_1]\n"
    assert "Wrote redacted log" in result.output


def test_redact_command_prints_redacted_logs(tmp_path: Path) -> None:
    log = write_log(tmp_path, "user=jane@example.com\n")

    result = runner.invoke(app, ["redact", str(log)])

    assert result.exit_code == 0
    assert result.output == "user=[EMAIL_1]\n"


def test_analyze_command_runs_safety_redaction_and_analysis(tmp_path: Path) -> None:
    log = write_log(
        tmp_path,
        "ERROR user jane@example.com timeout 500\n"
        "ERROR user jane@example.com timeout 500\n",
    )

    result = runner.invoke(app, ["analyze", str(log)])

    assert result.exit_code == 0
    assert "Safety Check" in result.output
    assert "SAFE" in result.output
    assert "Analysis Summary" in result.output
    assert "Findings" in result.output
    assert "Likely issue category: network" in result.output
    assert "Most frequent issue: ERROR user [EMAIL_1] timeout" in result.output
    assert "500" in result.output


def test_analyze_command_highlights_warning_status(tmp_path: Path) -> None:
    log = write_log(
        tmp_path,
        "ERROR aws issue AKIAABCDEFGHIJKLMNOP timeout 500\n",
    )

    result = runner.invoke(app, ["analyze", str(log)])

    assert result.exit_code == 0
    assert "WARN" in result.output
    assert "AWS-style key detected" in result.output


def test_analyze_command_blocks_private_keys_without_force(tmp_path: Path) -> None:
    log = write_log(
        tmp_path,
        "ERROR leaked key\n"
        "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----\n",
    )

    result = runner.invoke(app, ["analyze", str(log)])

    assert result.exit_code == 1
    assert "BLOCK" in result.output
    assert "Analysis blocked: possible private key detected" in result.output
    assert "Run with --force-local if you understand the risk." in result.output


def test_analyze_command_allows_blocked_logs_with_force_local(tmp_path: Path) -> None:
    log = write_log(
        tmp_path,
        "ERROR leaked key\n"
        "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----\n",
    )

    result = runner.invoke(app, ["analyze", str(log), "--force-local"])

    assert result.exit_code == 0
    assert "BLOCK" in result.output
    assert "Most frequent issue" in result.output


def test_analyze_command_accepts_allow_ai_stub(tmp_path: Path) -> None:
    log = write_log(tmp_path, "ERROR timeout 500\n")

    result = runner.invoke(app, ["analyze", str(log), "--allow-ai"])

    assert result.exit_code == 0
    assert "AI summaries are not implemented in the MVP." in result.output


def test_analyze_command_uses_redacted_text_internally(tmp_path: Path) -> None:
    log = write_log(
        tmp_path,
        "ERROR user jane@example.com token sk_test_1234567890abcdef "
        "url https://api.example.com/v1/users path /var/log/app.log timeout 500\n",
    )

    result = runner.invoke(app, ["analyze", str(log), "--allow-ai"])

    assert result.exit_code == 0
    assert "jane@example.com" not in result.output
    assert "sk_test_1234567890abcdef" not in result.output
    assert "https://api.example.com/v1/users" not in result.output
    assert "/var/log/app.log" not in result.output
    assert "[EMAIL_1]" in result.output
    assert "[API_KEY_1]" in result.output
    assert "[URL_1]" in result.output
    assert "[FILE_PATH_1]" in result.output
    assert "AI summaries are not implemented in the MVP." in result.output


def test_analyze_command_passes_only_redacted_text_to_analyzer(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    captured: dict[str, str] = {}

    def fake_analyze_text(text: str) -> dict[str, object]:
        captured["text"] = text
        return {
            "top_errors": [{"line": text.strip(), "count": 1}],
            "keyword_counts": {
                "error": 1,
                "exception": 0,
                "failed": 0,
                "failure": 0,
                "timeout": 1,
            },
            "status_codes": {"500": 1},
            "likely_issue": "network",
            "summary": "Most frequent issue: redacted timeout (1 occurrence).",
        }

    monkeypatch.setattr("safelog.main.analyze_text", fake_analyze_text)
    log = write_log(tmp_path, "ERROR jane@example.com timeout 500\n")

    result = runner.invoke(app, ["analyze", str(log), "--allow-ai"])

    assert result.exit_code == 0
    assert captured["text"] == "ERROR [EMAIL_1] timeout 500\n"


def test_analyze_command_json_outputs_valid_json_only(tmp_path: Path) -> None:
    log = write_log(
        tmp_path,
        "ERROR user jane@example.com timeout 500\n"
        "ERROR user jane@example.com timeout 500\n",
    )

    result = runner.invoke(app, ["analyze", str(log), "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert set(payload) == {
        "scan_results",
        "safety",
        "top_errors",
        "keyword_counts",
        "status_codes",
        "likely_issue",
        "summary",
    }
    assert payload["scan_results"]["emails"] == 2
    assert payload["safety"]["status"] == "safe"
    assert payload["top_errors"] == [
        {"line": "ERROR user [EMAIL_1] timeout 500", "count": 2},
    ]
    assert payload["status_codes"] == {"500": 2}
    assert "Safety Check" not in result.stdout
    assert result.stderr == ""


def test_analyze_command_markdown_outputs_report(tmp_path: Path) -> None:
    log = write_log(tmp_path, "ERROR user jane@example.com timeout 500\n")

    result = runner.invoke(app, ["analyze", str(log), "--markdown"])

    assert result.exit_code == 0
    assert result.stdout.startswith("# SafeLog Report\n")
    assert "## Scan Summary" in result.stdout
    assert "## Safety" in result.stdout
    assert "## Analysis Summary" in result.stdout
    assert "- ERROR user [EMAIL_1] timeout 500 (1)" in result.stdout


def test_analyze_command_writes_json_report_to_out_file(tmp_path: Path) -> None:
    log = write_log(tmp_path, "ERROR user jane@example.com timeout 500\n")
    out = tmp_path / "report.json"

    result = runner.invoke(app, ["analyze", str(log), "--json", "--out", str(out)])

    assert result.exit_code == 0
    assert result.stdout == ""
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["top_errors"][0]["line"] == "ERROR user [EMAIL_1] timeout 500"


def test_analyze_command_writes_markdown_report_to_out_file(tmp_path: Path) -> None:
    log = write_log(tmp_path, "ERROR timeout 500\n")
    out = tmp_path / "report.md"

    result = runner.invoke(app, ["analyze", str(log), "--markdown", "--out", str(out)])

    assert result.exit_code == 0
    assert result.stdout == ""
    assert out.read_text(encoding="utf-8").startswith("# SafeLog Report\n")


def test_analyze_command_out_requires_report_format(tmp_path: Path) -> None:
    log = write_log(tmp_path, "ERROR timeout 500\n")
    out = tmp_path / "report.md"

    result = runner.invoke(app, ["analyze", str(log), "--out", str(out)])

    assert result.exit_code == 2
    assert "Use --json or --markdown with --out." in result.stderr


def test_analyze_command_json_blocked_returns_exit_code_one(tmp_path: Path) -> None:
    log = write_log(
        tmp_path,
        "ERROR leaked key\n"
        "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----\n",
    )

    result = runner.invoke(app, ["analyze", str(log), "--json"])

    assert result.exit_code == 1
    assert result.stdout == ""
    assert "Analysis blocked: possible private key detected" in result.stderr
    assert "Run with --force-local if you understand the risk." in result.stderr


def test_analyze_command_fail_on_never_allows_blocked_analysis(tmp_path: Path) -> None:
    log = write_log(
        tmp_path,
        "ERROR leaked key\n"
        "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----\n",
    )

    result = runner.invoke(app, ["analyze", str(log), "--fail-on", "never"])

    assert result.exit_code == 0
    assert "BLOCK" in result.output
    assert "Most frequent issue" in result.output


def test_analyze_command_fail_on_warn_fails_for_warning(tmp_path: Path) -> None:
    log = write_log(tmp_path, "WARN aws key AKIAABCDEFGHIJKLMNOP\n")

    result = runner.invoke(app, ["analyze", str(log), "--fail-on", "warn"])

    assert result.exit_code == 1
    assert "AWS-style key detected" in result.output


def test_analyze_command_fail_on_block_allows_warning(tmp_path: Path) -> None:
    log = write_log(tmp_path, "WARN aws key AKIAABCDEFGHIJKLMNOP\n")

    result = runner.invoke(app, ["analyze", str(log), "--fail-on", "block"])

    assert result.exit_code == 0
    assert "WARN" in result.output


def test_analyze_command_invalid_fail_on_returns_exit_code_two(tmp_path: Path) -> None:
    log = write_log(tmp_path, "ERROR timeout 500\n")

    result = runner.invoke(app, ["analyze", str(log), "--fail-on", "sometimes"])

    assert result.exit_code == 2
    assert "Invalid --fail-on" in result.stderr


def test_analyze_command_oversized_file_returns_exit_code_two(tmp_path: Path) -> None:
    log = write_log(tmp_path, "ERROR timeout 500\n")

    result = runner.invoke(app, ["analyze", str(log), "--max-size", "1B"])

    assert result.exit_code == 2
    assert "File error:" in result.stderr
    assert "exceeds --max-size" in result.stderr


def test_analyze_command_accepts_simple_max_size_units(tmp_path: Path) -> None:
    log = write_log(tmp_path, "ERROR timeout 500\n")

    result = runner.invoke(app, ["analyze", str(log), "--max-size", "500KB"])

    assert result.exit_code == 0


def test_analyze_command_missing_file_returns_exit_code_two(tmp_path: Path) -> None:
    missing = tmp_path / "missing.log"

    result = runner.invoke(app, ["analyze", str(missing)])

    assert result.exit_code == 2
    assert result.stdout == ""
    assert "File error:" in result.stderr
