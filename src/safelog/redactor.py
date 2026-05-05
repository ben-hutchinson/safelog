import re
from pathlib import Path

from safelog.rules import CustomRule
from safelog.scanner import DETECTION_PATTERNS


REDACTION_ORDER: tuple[str, ...] = (
    "private_keys",
    "jwts",
    "aws_keys",
    "api_keys",
    "emails",
    "urls",
    "ips",
    "file_paths",
    "domains",
    "uuids",
)

PLACEHOLDER_NAMES: dict[str, str] = {
    "emails": "EMAIL",
    "ips": "IP",
    "jwts": "JWT",
    "aws_keys": "AWS_KEY",
    "api_keys": "API_KEY",
    "private_keys": "PRIVATE_KEY",
    "urls": "URL",
    "domains": "DOMAIN",
    "file_paths": "FILE_PATH",
    "uuids": "UUID",
}


def _redact_pattern(
    text: str,
    label: str,
    pattern: re.Pattern[str],
    mappings: dict[str, dict[str, str]],
) -> str:
    pattern_mapping = mappings.setdefault(label, {})

    def replace(match: re.Match[str]) -> str:
        value = match.group(0)
        if value not in pattern_mapping:
            pattern_mapping[value] = f"[{label}_{len(pattern_mapping) + 1}]"
        return pattern_mapping[value]

    return pattern.sub(replace, text)


def redact_text(
    text: str,
    custom_rules: list[CustomRule] | None = None,
) -> str:
    """Return text with sensitive values replaced by deterministic placeholders."""
    redacted = text
    mappings: dict[str, dict[str, str]] = {}
    for pattern_name in REDACTION_ORDER:
        redacted = _redact_pattern(
            redacted,
            PLACEHOLDER_NAMES[pattern_name],
            DETECTION_PATTERNS[pattern_name],
            mappings,
        )
    for rule in custom_rules or []:
        redacted = _redact_pattern(
            redacted,
            rule.placeholder,
            rule.pattern,
            mappings,
        )
    return redacted


def redact_file(
    path: str,
    custom_rules: list[CustomRule] | None = None,
) -> str:
    """Read a log file and return redacted text."""
    return redact_text(
        Path(path).read_text(encoding="utf-8", errors="replace"),
        custom_rules,
    )
