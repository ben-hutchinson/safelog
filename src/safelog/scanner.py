import re
from pathlib import Path


PathLike = str | Path

EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
)
IPV4_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b",
)
JWT_PATTERN = re.compile(
    r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",
)
AWS_KEY_PATTERN = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
API_KEY_PATTERN = re.compile(
    r"\b(?:sk|pk|ghp|xoxb)_[A-Za-z0-9_+=/-]{8,}\b",
)
PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
    re.DOTALL,
)
UUID_PATTERN = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
    r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b",
)

URL_PATTERN = re.compile(r"\bhttps?://[^\s]+")
DOMAIN_PATTERN = re.compile(r"(?<![@/.])\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b")
FILE_PATH_PATTERN = re.compile(r"(?<![\w.:/-])(?:/[\w.-]+)+")

DETECTION_PATTERNS: dict[str, re.Pattern[str]] = {
    "emails": EMAIL_PATTERN,
    "ips": IPV4_PATTERN,
    "ipv4_addresses": IPV4_PATTERN,
    "urls": URL_PATTERN,
    "domains": DOMAIN_PATTERN,
    "jwts": JWT_PATTERN,
    "aws_keys": AWS_KEY_PATTERN,
    "api_keys": API_KEY_PATTERN,
    "private_keys": PRIVATE_KEY_PATTERN,
    "file_paths": FILE_PATH_PATTERN,
    "uuids": UUID_PATTERN,
}


def read_log_file(path: PathLike) -> str:
    """Read log text without failing on undecodable bytes."""
    return Path(path).read_text(encoding="utf-8", errors="replace")


def count_emails(text: str) -> int:
    return len(EMAIL_PATTERN.findall(text))


def count_ips(text: str) -> int:
    return len(IPV4_PATTERN.findall(text))


def count_urls(text: str) -> int:
    return len(URL_PATTERN.findall(text))


def count_domains(text: str) -> int:
    excluded_spans = [
        match.span()
        for pattern in (EMAIL_PATTERN, URL_PATTERN, JWT_PATTERN, FILE_PATH_PATTERN)
        for match in pattern.finditer(text)
    ]
    return sum(
        not any(
            start >= excluded_start and end <= excluded_end
            for excluded_start, excluded_end in excluded_spans
        )
        for start, end in (match.span() for match in DOMAIN_PATTERN.finditer(text))
    )


def count_jwts(text: str) -> int:
    return len(JWT_PATTERN.findall(text))


def count_aws_keys(text: str) -> int:
    return len(AWS_KEY_PATTERN.findall(text))


def count_api_keys(text: str) -> int:
    return len(API_KEY_PATTERN.findall(text))


def count_private_keys(text: str) -> int:
    return len(PRIVATE_KEY_PATTERN.findall(text))


def count_file_paths(text: str) -> int:
    return len(FILE_PATH_PATTERN.findall(text))


def count_uuids(text: str) -> int:
    return len(UUID_PATTERN.findall(text))


def scan_text(text: str) -> dict[str, int]:
    """Return structured counts for supported sensitive patterns."""
    return {
        "emails": count_emails(text),
        "ips": count_ips(text),
        "urls": count_urls(text),
        "domains": count_domains(text),
        "jwts": count_jwts(text),
        "aws_keys": count_aws_keys(text),
        "api_keys": count_api_keys(text),
        "private_keys": count_private_keys(text),
        "file_paths": count_file_paths(text),
        "uuids": count_uuids(text),
    }


def scan_file(path: str) -> dict[str, int]:
    """Scan a log file and return structured sensitive pattern counts."""
    return scan_text(read_log_file(path))
