import re
from collections import Counter
from pathlib import Path


ERROR_KEYWORDS: tuple[str, ...] = ("error", "exception", "failed", "failure", "timeout")
HTTP_STATUS_PATTERN = re.compile(r"(?<![\d.])([1-5]\d{2})(?![\d.])")


def _non_empty_lines(text: str) -> list[str]:
    return [line for line in text.splitlines() if line.strip()]


def _contains_error_keyword(line: str) -> bool:
    lowered = line.lower()
    return any(keyword in lowered for keyword in ERROR_KEYWORDS)


def _top_error_lines(lines: list[str]) -> list[dict[str, int | str]]:
    error_lines = [line for line in lines if _contains_error_keyword(line)]
    return [
        {"line": line, "count": count}
        for line, count in Counter(error_lines).most_common(3)
    ]


def _keyword_counts(lines: list[str]) -> dict[str, int]:
    lowered_lines = [line.lower() for line in lines]
    return {
        keyword: sum(keyword in line for line in lowered_lines)
        for keyword in ERROR_KEYWORDS
    }


def _status_code_counts(text: str) -> dict[str, int]:
    return dict(Counter(HTTP_STATUS_PATTERN.findall(text)))


def _issue_label(line: object) -> str:
    without_status = HTTP_STATUS_PATTERN.sub("", str(line))
    return " ".join(without_status.split())


def _summary(top_errors: list[dict[str, int | str]]) -> str:
    if not top_errors:
        return "No errors detected."

    issue = top_errors[0]
    count = issue["count"]
    suffix = "occurrence" if count == 1 else "occurrences"
    return f"Most frequent issue: {_issue_label(issue['line'])} ({count} {suffix})."


def _likely_issue(lines: list[str]) -> str:
    joined = " ".join(lines).lower()
    categories = {
        "database": ("database", "db", "sql", "query", "connection pool"),
        "auth": ("auth", "permission", "denied", "unauthorized", "forbidden", "login"),
        "memory": ("memory", "oom", "out of memory"),
        "network": (
            "timeout",
            "connect",
            "connection",
            "dns",
            "refused",
            "unreachable",
        ),
    }
    for category, markers in categories.items():
        if any(marker in joined for marker in markers):
            return category
    return "general"


def analyze_text(text: str) -> dict[str, object]:
    """Analyze log text for repeated errors, keywords, and HTTP statuses."""
    lines = _non_empty_lines(text)
    top_errors = _top_error_lines(lines)
    return {
        "top_errors": top_errors,
        "keyword_counts": _keyword_counts(lines),
        "status_codes": _status_code_counts(text),
        "likely_issue": _likely_issue([str(item["line"]) for item in top_errors]),
        "summary": _summary(top_errors),
    }


def analyze_file(path: str) -> dict[str, object]:
    """Read a log file and return deterministic analysis results."""
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    return analyze_text(text)
