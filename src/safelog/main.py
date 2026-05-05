import json
import re
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from safelog.analyzer import analyze_text
from safelog.redactor import redact_file
from safelog.rules import CustomRule, RulesConfigError, load_custom_rules
from safelog.safety import check_safety
from safelog.scanner import scan_file


app = typer.Typer(help="Scan, redact, and analyze logs safely.")
console = Console()
error_console = Console(stderr=True)
FAIL_ON_VALUES = {"never", "warn", "block"}
SIZE_PATTERN = re.compile(r"^\s*(\d+)\s*(B|KB|MB|GB)?\s*$", re.IGNORECASE)
SIZE_UNITS = {
    "B": 1,
    "KB": 1024,
    "MB": 1024**2,
    "GB": 1024**3,
}


def _print_counts(title: str, counts: dict[str, int]) -> None:
    table = Table(title=title)
    table.add_column("Pattern", style="cyan")
    table.add_column("Count", justify="right")
    for name, count in counts.items():
        table.add_row(name.replace("_", " ").title(), str(count))
    console.print(table)


def _print_safety(safety: dict[str, str]) -> None:
    status = safety["status"]
    styles = {
        "safe": "green",
        "warn": "yellow",
        "block": "red",
    }
    labels = {
        "safe": "SAFE",
        "warn": "WARN",
        "block": "BLOCK",
    }
    style = styles.get(status, "white")
    label = labels.get(status, status.upper())
    console.print(
        Panel(
            f"[bold {style}]{label}[/bold {style}]\n{safety['reason']}",
            title="Safety Check",
            border_style=style,
        ),
    )


def _print_file_error(error: OSError) -> None:
    error_console.print(f"[red]File error:[/red] {error}")


def _exit_file_error(error: OSError) -> None:
    _print_file_error(error)
    raise typer.Exit(code=2)


def _print_usage_error(message: str) -> None:
    error_console.print(f"[red]Usage error:[/red] {message}")


def _exit_config_error(error: RulesConfigError) -> None:
    error_console.print(f"[red]Config error:[/red] {error}")
    raise typer.Exit(code=2)


def _load_rules(config: Path | None) -> list[CustomRule]:
    try:
        return load_custom_rules(config_path=config)
    except RulesConfigError as error:
        _exit_config_error(error)


def _parse_max_size(value: str) -> int:
    match = SIZE_PATTERN.match(value)
    if match is None:
        raise ValueError(f"Invalid --max-size value: {value}")

    amount = int(match.group(1))
    unit = (match.group(2) or "B").upper()
    return amount * SIZE_UNITS[unit]


def _check_file_size(path: Path, max_size: str) -> None:
    try:
        limit = _parse_max_size(max_size)
        actual_size = path.stat().st_size
    except ValueError as error:
        error_console.print(f"[red]File error:[/red] {error}")
        raise typer.Exit(code=2)
    except OSError as error:
        _exit_file_error(error)

    if actual_size > limit:
        error_console.print(
            f"[red]File error:[/red] {path} is {actual_size} bytes, "
            f"which exceeds --max-size {max_size}."
        )
        raise typer.Exit(code=2)


def _json_payload(
    scan_results: dict[str, int],
    safety: dict[str, str],
    result: dict[str, object],
) -> dict[str, object]:
    return {
        "scan_results": scan_results,
        "safety": safety,
        "top_errors": result["top_errors"],
        "keyword_counts": result["keyword_counts"],
        "status_codes": result["status_codes"],
        "likely_issue": result["likely_issue"],
        "summary": result["summary"],
    }


def _markdown_counts(counts: dict[str, object]) -> list[str]:
    if not counts:
        return ["- None"]
    return [f"- {key}: {value}" for key, value in counts.items()]


def _markdown_report(
    scan_results: dict[str, int],
    safety: dict[str, str],
    result: dict[str, object],
) -> str:
    top_errors = result["top_errors"]
    lines = [
        "# SafeLog Report",
        "",
        "## Scan Summary",
        *_markdown_counts(scan_results),
        "",
        "## Safety",
        f"- Status: {safety['status']}",
        f"- Reason: {safety['reason']}",
        "",
        "## Analysis Summary",
        f"- {result['summary']}",
        f"- Likely issue category: {result['likely_issue']}",
        "",
        "## Top Repeated Errors",
    ]
    if isinstance(top_errors, list) and top_errors:
        for item in top_errors:
            if isinstance(item, dict):
                lines.append(f"- {item['line']} ({item['count']})")
    else:
        lines.append("- None")

    lines.extend(["", "## Keyword Counts"])
    keyword_counts = result["keyword_counts"]
    if isinstance(keyword_counts, dict):
        lines.extend(_markdown_counts(keyword_counts))

    lines.extend(["", "## HTTP Status Codes"])
    status_codes = result["status_codes"]
    if isinstance(status_codes, dict):
        lines.extend(_markdown_counts(status_codes))

    return "\n".join(lines) + "\n"


def _write_report(path: Path, content: str) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    except OSError as error:
        _exit_file_error(error)


def _should_fail_for_safety(status: str, fail_on: str) -> bool:
    if fail_on == "never":
        return False
    if fail_on == "warn":
        return status in {"warn", "block"}
    return status == "block"


def _print_analysis_summary(summary: object) -> None:
    console.print("[bold]Analysis Summary[/bold]")
    console.print(f"- {summary}")


def _print_likely_issue(likely_issue: object) -> None:
    console.print(f"- Likely issue category: {likely_issue}")


def _print_top_errors(top_errors: list[object]) -> None:
    if not top_errors:
        return

    console.print("[bold]Findings[/bold]")
    for item in top_errors:
        if isinstance(item, dict):
            console.print(f"- {item['line']} ({item['count']})")


@app.command()
def scan(
    file: Path,
    config: Path | None = typer.Option(
        None,
        "--config",
        help="Path to safelog.toml custom rules.",
    ),
) -> None:
    """Scan a log file for sensitive data."""
    custom_rules = _load_rules(config)
    try:
        results = scan_file(str(file), custom_rules)
    except OSError as error:
        _exit_file_error(error)
    _print_counts("Scan Results", results)


@app.command()
def redact(
    file: Path,
    out: Path | None = typer.Option(
        None, "--out", help="Write redacted logs to a file."
    ),
    config: Path | None = typer.Option(
        None,
        "--config",
        help="Path to safelog.toml custom rules.",
    ),
) -> None:
    """Print or write a redacted version of a log file."""
    custom_rules = _load_rules(config)
    try:
        redacted = redact_file(str(file), custom_rules)
    except OSError as error:
        _exit_file_error(error)

    if out is not None:
        try:
            out.write_text(redacted, encoding="utf-8")
        except OSError as error:
            _exit_file_error(error)
        console.print(f"Wrote redacted log to {out}")
        return

    console.print(redacted, end="")


@app.command()
def analyze(
    file: Path,
    force_local: bool = typer.Option(
        False,
        "--force-local",
        help="Analyze locally even when safety checks block by default.",
    ),
    allow_ai: bool = typer.Option(
        False,
        "--allow-ai",
        help="Reserved for future AI summaries; no AI is called in the MVP.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Print machine-readable JSON analysis output only.",
    ),
    markdown: bool = typer.Option(
        False,
        "--markdown",
        help="Print a Markdown analysis report.",
    ),
    out: Path | None = typer.Option(
        None,
        "--out",
        help="Write the selected report format to a file.",
    ),
    fail_on: str = typer.Option(
        "block",
        "--fail-on",
        help="When to fail: never, warn, block.",
    ),
    max_size: str = typer.Option(
        "5MB",
        "--max-size",
        help="Maximum log file size, e.g. 500KB, 5MB, 1GB.",
    ),
    config: Path | None = typer.Option(
        None,
        "--config",
        help="Path to safelog.toml custom rules.",
    ),
) -> None:
    """Analyze a log file after scanning, safety checks, and redaction."""
    if json_output and markdown:
        _print_usage_error("Use only one output format: --json or --markdown.")
        raise typer.Exit(code=2)
    if out is not None and not (json_output or markdown):
        _print_usage_error("Use --json or --markdown with --out.")
        raise typer.Exit(code=2)
    if fail_on not in FAIL_ON_VALUES:
        _print_usage_error("Invalid --fail-on value. Use: never, warn, block.")
        raise typer.Exit(code=2)

    _check_file_size(file, max_size)
    custom_rules = _load_rules(config)

    try:
        scan_results = scan_file(str(file), custom_rules)
    except OSError as error:
        _exit_file_error(error)

    safety = check_safety(scan_results, custom_rules)
    report_mode = json_output or markdown
    if not report_mode:
        _print_safety(safety)

    if _should_fail_for_safety(safety["status"], fail_on) and not force_local:
        message = (
            f"{safety['reason']}\nRun with --force-local if you understand the risk."
        )
        if json_output:
            print(message, file=sys.stderr)
        else:
            if safety["status"] == "block":
                console.print(
                    "[red]Run with --force-local if you understand the risk.[/red]"
                )
        raise typer.Exit(code=1)

    try:
        redacted = redact_file(str(file), custom_rules)
    except OSError as error:
        _exit_file_error(error)

    result = analyze_text(redacted)
    payload = _json_payload(scan_results, safety, result)
    if json_output:
        content = json.dumps(payload, sort_keys=True) + "\n"
        if out is not None:
            _write_report(out, content)
        else:
            print(content, end="")
        return

    if markdown:
        content = _markdown_report(scan_results, safety, result)
        if out is not None:
            _write_report(out, content)
        else:
            print(content, end="")
        return

    _print_analysis_summary(result["summary"])
    _print_likely_issue(result["likely_issue"])

    top_errors = result["top_errors"]
    if isinstance(top_errors, list) and top_errors:
        _print_top_errors(top_errors)

    keyword_counts = result["keyword_counts"]
    if isinstance(keyword_counts, dict):
        _print_counts("Keyword Counts", keyword_counts)

    status_codes = result["status_codes"]
    if isinstance(status_codes, dict) and status_codes:
        _print_counts("HTTP Status Codes", status_codes)

    if allow_ai:
        console.print("AI summaries are not implemented in the MVP.")


if __name__ == "__main__":
    app()
