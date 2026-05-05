import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 fallback
    import tomli as tomllib


RULE_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9_]*$")
PLACEHOLDER_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]*$")
SEVERITIES = {"safe", "warn", "block"}


class RulesConfigError(ValueError):
    """Raised when safelog.toml custom rules are invalid."""


@dataclass(frozen=True)
class CustomRule:
    name: str
    pattern: re.Pattern[str]
    placeholder: str
    severity: str = "safe"
    description: str = ""

    @property
    def key(self) -> str:
        return f"custom_{self.name}"

    @classmethod
    def from_config(
        cls,
        name: str,
        pattern: str,
        placeholder: str | None = None,
        severity: str = "safe",
        description: str = "",
    ) -> "CustomRule":
        if not RULE_NAME_PATTERN.fullmatch(name):
            raise RulesConfigError(f"Invalid rule name: {name}")
        if not isinstance(pattern, str) or not pattern:
            raise RulesConfigError(f"Rule {name} requires a string pattern.")

        try:
            compiled = re.compile(pattern)
        except re.error as error:
            raise RulesConfigError(f"Invalid regex for rule {name}: {error}") from error

        resolved_placeholder = placeholder or name.upper()
        if not PLACEHOLDER_PATTERN.fullmatch(resolved_placeholder):
            raise RulesConfigError(f"Invalid placeholder for rule {name}.")
        if severity not in SEVERITIES:
            raise RulesConfigError(f"Invalid severity for rule {name}: {severity}")
        if not isinstance(description, str):
            raise RulesConfigError(f"Invalid description for rule {name}.")

        return cls(
            name=name,
            pattern=compiled,
            placeholder=resolved_placeholder,
            severity=severity,
            description=description,
        )


def find_config(start: Path | None = None) -> Path | None:
    """Find safelog.toml by walking upward from start or cwd."""
    current = (start or Path.cwd()).resolve()
    if current.is_file():
        current = current.parent

    for directory in (current, *current.parents):
        candidate = directory / "safelog.toml"
        if candidate.exists():
            return candidate
    return None


def _read_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            parsed = tomllib.load(handle)
    except tomllib.TOMLDecodeError as error:
        raise RulesConfigError(f"Invalid TOML in {path}: {error}") from error
    except OSError as error:
        raise RulesConfigError(f"Could not read config {path}: {error}") from error

    if not isinstance(parsed, dict):
        raise RulesConfigError(f"Invalid config in {path}.")
    return parsed


def load_custom_rules(
    config_path: str | Path | None = None,
    start: Path | None = None,
) -> list[CustomRule]:
    """Load add-only custom rules from safelog.toml."""
    path = Path(config_path) if config_path is not None else find_config(start)
    if path is None:
        return []
    if not path.exists():
        raise RulesConfigError(f"Config file not found: {path}")

    parsed = _read_toml(path)
    rules_table = parsed.get("rules", {})
    if not isinstance(rules_table, dict):
        raise RulesConfigError("Config [rules] must be a table.")

    rules: list[CustomRule] = []
    for name, raw_rule in rules_table.items():
        if not isinstance(raw_rule, dict):
            raise RulesConfigError(f"Rule {name} must be a table.")
        rules.append(
            CustomRule.from_config(
                name=name,
                pattern=raw_rule.get("pattern"),
                placeholder=raw_rule.get("placeholder"),
                severity=raw_rule.get("severity", "safe"),
                description=raw_rule.get("description", ""),
            )
        )
    return rules
