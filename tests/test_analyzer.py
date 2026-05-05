from pathlib import Path

from safelog.analyzer import analyze_file, analyze_text


def test_analyze_text_detects_repeated_error_lines_top_three() -> None:
    text = "\n".join(
        [
            "ERROR database timeout",
            "ERROR database timeout",
            "failed to connect cache",
            "failed to connect cache",
            "exception loading settings",
            "exception loading settings",
            "timeout waiting for worker",
            "INFO request completed",
        ],
    )

    result = analyze_text(text)

    assert result["top_errors"] == [
        {"line": "ERROR database timeout", "count": 2},
        {"line": "failed to connect cache", "count": 2},
        {"line": "exception loading settings", "count": 2},
    ]


def test_analyze_text_counts_error_keywords() -> None:
    result = analyze_text(
        "ERROR database timeout\n"
        "exception in task runner\n"
        "failed login attempt\n"
        "payment failure received\n"
        "INFO healthy\n",
    )

    assert result["keyword_counts"] == {
        "error": 1,
        "exception": 1,
        "failed": 1,
        "failure": 1,
        "timeout": 1,
    }


def test_analyze_text_counts_http_status_codes() -> None:
    result = analyze_text(
        "GET /health 200\nGET /users 500\nGET /users 500\nGET /missing 404\n",
    )

    assert result["status_codes"] == {"200": 1, "500": 2, "404": 1}


def test_analyze_text_handles_empty_logs() -> None:
    assert analyze_text("") == {
        "top_errors": [],
        "keyword_counts": {
            "error": 0,
            "exception": 0,
            "failed": 0,
            "failure": 0,
            "timeout": 0,
        },
        "status_codes": {},
        "likely_issue": "general",
        "summary": "No errors detected.",
    }


def test_analyze_text_returns_deterministic_summary_for_mixed_logs() -> None:
    result = analyze_text(
        "INFO request completed 200\n"
        "ERROR database timeout 500\n"
        "ERROR database timeout 500\n"
        "failed to connect cache 503\n",
    )

    assert (
        result["summary"]
        == "Most frequent issue: ERROR database timeout (2 occurrences)."
    )
    assert result["likely_issue"] == "database"


def test_analyze_file_reads_from_path_string(tmp_path: Path) -> None:
    log = tmp_path / "sample.log"
    log.write_text("ERROR database timeout 500\n", encoding="utf-8")

    result = analyze_file(str(log))

    assert result["top_errors"] == [{"line": "ERROR database timeout 500", "count": 1}]


def test_analyze_text_handles_malformed_logs() -> None:
    result = analyze_text("not a standard log line\x00\x00\n??? failed ??? 500\n")

    assert result["top_errors"] == [{"line": "??? failed ??? 500", "count": 1}]
    assert result["keyword_counts"]["failed"] == 1
    assert result["status_codes"] == {"500": 1}


def test_analyze_text_handles_large_inputs_deterministically() -> None:
    text = "\n".join(
        ["ERROR database timeout 500" for _ in range(500)]
        + ["INFO request completed 200" for _ in range(500)],
    )

    result = analyze_text(text)

    assert result["top_errors"] == [
        {"line": "ERROR database timeout 500", "count": 500}
    ]
    assert result["keyword_counts"] == {
        "error": 500,
        "exception": 0,
        "failed": 0,
        "failure": 0,
        "timeout": 500,
    }
    assert result["status_codes"] == {"500": 500, "200": 500}
    assert (
        result["summary"]
        == "Most frequent issue: ERROR database timeout (500 occurrences)."
    )


def test_analyze_text_handles_logs_with_no_matches() -> None:
    result = analyze_text("INFO startup complete\nDEBUG cache warmed\n")

    assert result == {
        "top_errors": [],
        "keyword_counts": {
            "error": 0,
            "exception": 0,
            "failed": 0,
            "failure": 0,
            "timeout": 0,
        },
        "status_codes": {},
        "likely_issue": "general",
        "summary": "No errors detected.",
    }


def test_analyze_file_handles_malformed_bytes(tmp_path: Path) -> None:
    log = tmp_path / "malformed.log"
    log.write_bytes(b"ERROR bad byte \xff 500\n")

    result = analyze_file(str(log))

    assert result["keyword_counts"]["error"] == 1
    assert result["status_codes"] == {"500": 1}


def test_analyze_text_reports_likely_issue_categories() -> None:
    assert analyze_text("ERROR unauthorized login 401\n")["likely_issue"] == "auth"
    assert analyze_text("ERROR out of memory 500\n")["likely_issue"] == "memory"
    assert analyze_text("ERROR connection refused 503\n")["likely_issue"] == "network"
