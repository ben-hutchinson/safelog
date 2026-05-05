from pathlib import Path


PathLike = str | Path


def read_text_file(path: PathLike) -> str:
    """Read a UTF-8 text file from disk."""
    return Path(path).read_text(encoding="utf-8")


def non_empty_lines(text: str) -> list[str]:
    """Return non-empty lines without trailing newline characters."""
    return [line for line in text.splitlines() if line.strip()]


def normalize_log_message(line: str) -> str:
    """Remove a leading ISO-like timestamp so repeated messages group together."""
    parts = line.split(maxsplit=1)
    if len(parts) == 2 and "T" in parts[0] and parts[0].endswith("Z"):
        return parts[1]
    return line
