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
        name: object,
        pattern: object,
        label: object | None = None,
        placeholder: str | None = None,
        severity: str = "safe",
        description: str = "",
    ) -> "CustomRule":
        if not isinstance(name, str):
            raise RulesConfigError("Rule requires a string name.")
        if not RULE_NAME_PATTERN.fullmatch(name):
            raise RulesConfigError(f"Invalid rule name: {name}")
        if not isinstance(pattern, str) or not pattern:
            raise RulesConfigError(f"Rule {name} requires a string pattern.")
        if label is not None and not isinstance(label, str):
            raise RulesConfigError(f"Invalid label for rule {name}.")
        if placeholder is not None and not isinstance(placeholder, str):
            raise RulesConfigError(f"Invalid placeholder for rule {name}.")
        if label is not None and placeholder is not None and label != placeholder:
            raise RulesConfigError(
                f"Rule {name} cannot define different label and placeholder values."
            )

        try:
            compiled = re.compile(pattern)
        except re.error as error:
            raise RulesConfigError(f"Invalid regex for rule {name}: {error}") from error

        resolved_placeholder = label or placeholder or name.upper()
        if not PLACEHOLDER_PATTERN.fullmatch(resolved_placeholder):
            if label is not None:
                raise RulesConfigError(f"Invalid label for rule {name}.")
            raise RulesConfigError(f"Invalid placeholder for rule {name}.")
        if not isinstance(severity, str) or severity not in SEVERITIES:
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


def _load_rules_array(raw_rules: list[Any]) -> list[CustomRule]:
    rules: list[CustomRule] = []
    seen_names: set[str] = set()
    for index, raw_rule in enumerate(raw_rules, start=1):
        if not isinstance(raw_rule, dict):
            raise RulesConfigError(f"Rule entry {index} must be a table.")
        rule = CustomRule.from_config(
            name=raw_rule.get("name"),
            pattern=raw_rule.get("pattern"),
            label=raw_rule.get("label"),
            placeholder=raw_rule.get("placeholder"),
            severity=raw_rule.get("severity", "safe"),
            description=raw_rule.get("description", ""),
        )
        if rule.name in seen_names:
            raise RulesConfigError(f"Duplicate rule name: {rule.name}")
        seen_names.add(rule.name)
        rules.append(rule)
    return rules


def _load_rules_table(rules_table: dict[str, Any]) -> list[CustomRule]:
    rules: list[CustomRule] = []
    for name, raw_rule in rules_table.items():
        if not isinstance(raw_rule, dict):
            raise RulesConfigError(f"Rule {name} must be a table.")
        rules.append(
            CustomRule.from_config(
                name=name,
                pattern=raw_rule.get("pattern"),
                label=raw_rule.get("label"),
                placeholder=raw_rule.get("placeholder"),
                severity=raw_rule.get("severity", "safe"),
                description=raw_rule.get("description", ""),
            )
        )
    return rules


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
    raw_rules = parsed.get("rules", {})
    if isinstance(raw_rules, list):
        return _load_rules_array(raw_rules)
    if isinstance(raw_rules, dict):
        return _load_rules_table(raw_rules)
    raise RulesConfigError("Config rules must be an array of tables or a table.")
